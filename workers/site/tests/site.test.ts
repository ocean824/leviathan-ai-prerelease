import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { assertSiteFacts, missingFacts } from "../src/facts.mjs";

const pages: Record<string, string> = {
  "/": "Trading and analysis platform | Leviathan AI",
  "/app": "Web app coming soon | Leviathan AI",
  "/privacy": "Privacy policy | Leviathan AI",
  "/terms": "Terms of service | Leviathan AI",
  "/contact": "Contact | Leviathan AI",
  "/risk-disclosure": "Trading risk disclosure | Leviathan AI",
  "/data-deletion": "Data deletion | Leviathan AI",
  "/security": "Security | Leviathan AI",
  "/cookies": "Cookies | Leviathan AI",
  "/subprocessors": "Subprocessors | Leviathan AI",
  "/site.css": "",
};

function env() {
  return { ASSETS: { fetch: async (request: Request) => {
    const title = pages[new URL(request.url).pathname];
    return title ? new Response(`<!doctype html><title>${title}</title>`, { headers: { "Content-Type": "text/html" } }) : new Response("missing", { status: 404 });
  } } };
}

describe("Leviathan public site Worker", () => {
  it.each(Object.keys(pages))("serves %s through extensionless Static Assets mapping", async (route) => {
    let requested = "";
    const testEnv = { ASSETS: { fetch: async (request: Request) => {
      requested = new URL(request.url).pathname;
      const css = route === "/site.css";
      return new Response(css ? "body { color: black; }" : `<!doctype html><title>${pages[route]}</title>`, {
        headers: { "Content-Type": css ? "text/css" : "text/html" },
      });
    } } };
    const response = await worker.fetch(new Request(`https://site.example${route}`), testEnv as never);
    expect(response.status).toBe(200);
    expect(requested).toBe(route);
    if (route === "/site.css") expect(response.headers.get("Content-Type")).toContain("text/css");
    else expect(await response.text()).toContain(`<title>${pages[route]}</title>`);
  });

  it("returns 404 for unknown paths and applies security headers", async () => {
    const response = await worker.fetch(new Request("https://site.example/nope"), env() as never);
    expect(response.status).toBe(404);
    expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
    expect(response.headers.get("Strict-Transport-Security")).toContain("max-age=");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(response.headers.get("Referrer-Policy")).toBe("strict-origin-when-cross-origin");
  });

  it("adds security headers to assets and rejects methods other than GET and HEAD", async () => {
    const response = await worker.fetch(new Request("https://site.example/", { method: "HEAD" }), env() as never);
    expect(response.status).toBe(200);
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
    const rejected = await worker.fetch(new Request("https://site.example/", { method: "POST" }), env() as never);
    expect(rejected.status).toBe(405);
    expect(rejected.headers.get("Content-Security-Policy")).toContain("default-src 'self'");
  });
});

describe("site facts gate", () => {
  const complete = { company: { legal_name: { value: "Lossless Holdings, LLC", owner_confirmation_required: false }, formation_state: "Delaware", mailing_address: "1 Example Street", support_email: "support@example.test", regulatory_status: "No broker-dealer or investment-adviser registration", web_backend_host: "Cloudflare (Workers and Containers)", domain: "example.test", effective_date: "2026-10-09" }, retention: { account_deletion_days: "30", legal_retention_years: "7" }, refund_policy: "Refunds are available as required by law.", billing: { cancellation_method: "email" } };
  it("returns SITE_FACTS_INCOMPLETE for missing or unconfirmed facts", () => {
    const missing = missingFacts({ company: { ...complete.company, legal_name: { ...complete.company.legal_name, owner_confirmation_required: true }, support_email: "[REQUIRED: public support email]" } });
    expect(missing).toContain("company.legal_name");
    expect(missing).toContain("company.support_email");
    expect(() => assertSiteFacts({ company: {} })).toThrowError(/SITE_FACTS_INCOMPLETE/);
  });
  it("accepts complete facts only after confirmation", () => {
    expect(missingFacts(complete)).toEqual([]);
    expect(() => assertSiteFacts(complete)).not.toThrow();
  });
  it.each([
    ["support_email", "company.support_email", "not-an-email"],
    ["support_email mailto prefix", "company.support_email", "mailto:support@example.test"],
    ["effective_date", "company.effective_date", "soon"],
    ["domain", "company.domain", "site.workers.dev"],
    ["account deletion period", "retention.account_deletion_days", "1000"],
    ["legal retention period", "retention.legal_retention_years", "0"],
    ["cancellation method", "billing.cancellation_method", "account-controls"],
  ])("rejects malformed %s fact", (_name, path, value) => {
    const config = structuredClone(complete);
    const [group, key] = path.split(".");
    config[group][key] = value;
    expect(missingFacts(config)).toContain(path);
  });
});
