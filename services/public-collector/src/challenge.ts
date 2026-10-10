import { mkdir } from "node:fs/promises";
import { chromium } from "playwright-core";
import { HUMAN_ACTION_TIMEOUT_MS } from "./contracts.js";
import { chromeAvailable } from "../vendor/api-anything/dist/browser.js";
import { buildRequestPolicy } from "./robots.js";

export type UserActionOutcome = "completed" | "declined" | "timeout" | "window_failed" | "browser_unavailable";
export type ChallengePage = {
  isClosed(): boolean;
  goto(url: string, options: { waitUntil: "domcontentloaded"; timeout: number }): Promise<unknown>;
  locator(selector: string): { innerText(options: { timeout: number }): Promise<string> };
  setContent(html: string, options?: { waitUntil?: "domcontentloaded" }): Promise<void>;
  waitForFunction(fn: () => boolean, options: { timeout: number }): Promise<unknown>;
  close(): Promise<void>;
};
export type ChallengeContext = {
  newPage(): Promise<ChallengePage>;
  route?(pattern: string, handler: (route: { request(): { url(): string }; continue(): Promise<unknown>; abort(reason?: string): Promise<unknown> }) => Promise<unknown>): Promise<unknown>;
  close(): Promise<void>;
};
export type ChallengeOpener = (profileDir: string) => Promise<ChallengeContext>;

const challengeWords = /captcha|verify (that )?you are human|security check|unusual traffic|bot challenge|robot check/i;

export const openVisibleChallenge: ChallengeOpener = async (profileDir) =>
  chromium.launchPersistentContext(profileDir, {
    channel: "chrome",
    headless: false,
    args: ["--new-window"],
    timeout: 15_000,
  });

export async function waitForHumanChallenge(
  profileDir: string,
  url: string,
  notify: () => void,
  open?: ChallengeOpener,
  timeoutMs = HUMAN_ACTION_TIMEOUT_MS,
  challengeHosts: readonly string[] = [],
  dataDir = "",
): Promise<UserActionOutcome> {
  if (!open && !chromeAvailable()) return "browser_unavailable";
  const deadline = Date.now() + timeoutMs;
  await mkdir(profileDir, { recursive: true });
  let context: ChallengeContext;
  try {
    context = await (open ?? openVisibleChallenge)(profileDir);
  } catch {
    return "window_failed";
  }
  try {
    const policy = JSON.parse(process.env.LEVIATHAN_REQUEST_POLICY ?? "{}") as {
      allowedHosts?: string[];
      robots?: Record<string, { path: string; allow: boolean }[]>;
    };
    const challengePolicy = challengeHosts.length
      ? { allowedHosts: [...new Set([...challengeHosts, ...(policy.allowedHosts ?? [])])], robots: policy.robots ?? {} }
      : policy;
    await context.route?.("**/*", async (route) => {
      let allowed = false;
      try {
        const url = new URL(route.request().url());
        const host = url.hostname.toLowerCase();
        if (url.protocol === "https:" && challengePolicy.allowedHosts?.includes(host)) {
          let winner: { path: string; allow: boolean } | undefined;
          let specificity = -1;
          for (const rule of challengePolicy.robots?.[host] ?? []) {
            const end = rule.path.endsWith("$");
            const escaped = rule.path.slice(0, end ? -1 : undefined).replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
            if (!new RegExp(`^${escaped}${end ? "$" : ""}`).test(url.pathname + url.search)) continue;
            const weight = rule.path.replace(/[\*$]/g, "").length;
            if (weight > specificity || (weight === specificity && rule.allow && !winner?.allow)) {
              winner = rule;
              specificity = weight;
            }
          }
          allowed = winner?.allow ?? true;
        }
      } catch {
        allowed = false;
      }
      if (allowed) await route.continue();
      else await route.abort("blockedbyclient");
    });
    const challengePage = await context.newPage();
    await challengePage.goto(url, { waitUntil: "domcontentloaded", timeout: Math.min(15_000, timeoutMs) });
    const confirmPage = await context.newPage();
    await confirmPage.setContent(
      "<!doctype html><meta charset=utf-8><title>Leviathan check</title><main style='font:16px sans-serif;max-width:42rem;margin:4rem auto'><h1>Complete the site check</h1><p>Switch to the site tab, complete the check yourself, then return here and select Done. Leviathan will continue only if the original page shows its expected public content.</p><button id=done type=button style='font:inherit;padding:.8rem 1.4rem'>Done</button><script>document.getElementById('done').addEventListener('click',()=>document.body.dataset.confirmed='true')</script></main>",
      { waitUntil: "domcontentloaded" },
    );
    notify();
    try {
      await confirmPage.waitForFunction(() => document.body.dataset.confirmed === "true", { timeout: timeoutMs });
    } catch {
      return confirmPage.isClosed() ? "declined" : "timeout";
    }
    if (Date.now() >= deadline || challengePage.isClosed()) return "declined";
    let text = "";
    try {
      text = await challengePage.locator("body").innerText({ timeout: 2_000 });
    } catch {
      return "declined";
    }
    if (challengeWords.test(text) || text.trim().length < 30) return "declined";
    return "completed";
  } catch {
    return "window_failed";
  } finally {
    await context.close().catch(() => undefined);
  }
}
