import { readFile } from "node:fs/promises";

const cnnBody = await readFile(process.env.LEVIATHAN_TEST_CNN_BODY, "utf8");
globalThis.fetch = async (input) => {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
  if (url.pathname === "/robots.txt") return new Response("User-agent: *\nAllow: /\n", { status: 200 });
  if (url.hostname === "www.cnn.com" && url.pathname === "/markets/fear-and-greed") {
    return new Response(cnnBody, { status: 200, headers: { "content-type": "application/json" } });
  }
  return new Response("not found", { status: 404 });
};
