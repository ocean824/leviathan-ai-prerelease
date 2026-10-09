import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";

const bridge = readFileSync(new URL("../src-tauri/src/bridge.js", import.meta.url), "utf8")
  .replace("__CAPABILITY__", "a".repeat(64));
const calls = [];
const origin = "http://127.0.0.1:49123";
const window = {
  location: { origin },
  fetch: async (request) => {
    calls.push(request);
    return { status: 200 };
  },
};
class BrowserRequest extends Request {
  constructor(input, init) {
    super(typeof input === "string" && input.startsWith("/") ? origin + input : input, init);
  }
}
runInContext(bridge, createContext({ window, Request: BrowserRequest, Headers, URL }));

await window.fetch("/api/risk/status");
assert.equal(calls[0].headers.get("X-Leviathan-Capability"), "a".repeat(64));
assert.equal(calls[0].url, origin + "/api/risk/status");
await window.fetch("/");
assert.equal(calls[1].headers.get("X-Leviathan-Capability"), null);
await window.fetch("https://untrusted.example/api/risk/status");
assert.equal(calls[2].headers.get("X-Leviathan-Capability"), null);
console.log("bridge capability forwarding: 3 checks passed");
