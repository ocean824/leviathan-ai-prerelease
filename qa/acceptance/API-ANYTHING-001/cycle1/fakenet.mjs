// Preload (node --import) that replaces globalThis.fetch with an in-process fake internet.
// No socket is ever opened; every request is answered from the routes file named by AA_FAKENET
// and appended to AA_FAKENET_LOG, so a test can prove which URLs were (not) requested.
import { appendFileSync, readFileSync } from "node:fs";

const counters = new Map();

function load() {
  return JSON.parse(readFileSync(process.env.AA_FAKENET, "utf8"));
}

function pick(entry, key) {
  if (!Array.isArray(entry)) return entry;
  const n = counters.get(key) ?? 0;
  counters.set(key, n + 1);
  return entry[Math.min(n, entry.length - 1)];
}

globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
  const parsed = new URL(url);
  const headers = new Headers(init.headers ?? (typeof input === "object" && "headers" in input ? input.headers : undefined));
  appendFileSync(process.env.AA_FAKENET_LOG, JSON.stringify({
    url, host: parsed.hostname, path: parsed.pathname + parsed.search, method: (init.method ?? "GET").toUpperCase(),
    ua: headers.get("user-agent"), cookie: headers.get("cookie"), auth: headers.get("authorization"), redirect: init.redirect ?? null,
  }) + "\n");
  const world = load();
  const host = world.hosts?.[parsed.hostname];
  const respond = (spec) => {
    const body = spec.json !== undefined ? JSON.stringify(spec.json) : (spec.text ?? "");
    const h = new Headers(spec.headers ?? {});
    if (spec.json !== undefined && !h.has("content-type")) h.set("content-type", "application/json");
    if (spec.location) h.set("location", spec.location);
    if (spec.retry_after !== undefined) h.set("retry-after", String(spec.retry_after));
    const res = new Response([204, 205, 304].includes(spec.status ?? 200) ? null : body, { status: spec.status ?? 200, headers: h });
    Object.defineProperty(res, "url", { value: url });
    return res;
  };
  if (!host) return respond({ status: 404, text: "unknown host" });
  if (parsed.pathname === "/robots.txt") {
    const robots = pick(host.robots ?? null, `${parsed.hostname}/robots`);
    if (robots === null || robots === undefined) return respond({ status: 404, text: "" });
    if (typeof robots === "string") return respond({ status: 200, text: robots });
    return respond(robots);
  }
  const route = host.routes?.[parsed.pathname + parsed.search] ?? host.routes?.[parsed.pathname];
  if (route === undefined) return respond({ status: 404, text: "no route" });
  return respond(pick(route, `${parsed.hostname}${parsed.pathname}`));
};
