import { appendFileSync } from "node:fs";
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  const fakeOrigin = process.env.AA_TEST_LOOPBACK_URL;
  if (url.hostname === "www.cnn.com" && fakeOrigin) {
    if (url.pathname === "/robots.txt") return new Response("", { status: 404 });
    const target = new URL(url.pathname + url.search, fakeOrigin);
    const response = await originalFetch(target, init);
    appendFileSync(process.env.AA_LOG, JSON.stringify({ ev: "fake-fetch", url: url.href, status: response.status }) + "\n");
    return response;
  }
  return originalFetch(input, init);
};
