export interface Env {
  ASSETS: Fetcher;
}

const PAGES = new Set([
  "/", "/app", "/privacy", "/terms", "/contact", "/risk-disclosure",
  "/data-deletion", "/security", "/cookies", "/subprocessors",
]);

const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== "GET" && request.method !== "HEAD") {
      return withSecurity(new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } }));
    }
    const path = url.pathname.endsWith("/") && url.pathname !== "/"
      ? url.pathname.slice(0, -1) : url.pathname;
    if (path !== "/site.css" && !PAGES.has(path)) return withSecurity(new Response("Not found", { status: 404 }));
    const asset = new URL(request.url);
    asset.pathname = path;
    const response = await env.ASSETS.fetch(new Request(asset, request));
    return withSecurity(response);
  },
};

function withSecurity(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
