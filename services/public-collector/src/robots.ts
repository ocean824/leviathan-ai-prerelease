import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type RobotsRule = { path: string; allow: boolean };
export type RobotsSnapshot = { rules: RobotsRule[]; fetched_at: string };
export type RequestPolicy = {
  allowedHosts: string[];
  robots: Record<string, RobotsRule[]>;
};

const USER_AGENT = "LeviathanPublicCollector";
const CACHE_TTL_MS = 60 * 60 * 1000;
const cache = new Map<string, RobotsSnapshot>();

function pathPattern(rule: string): RegExp {
  const endAnchored = rule.endsWith("$");
  const body = endAnchored ? rule.slice(0, -1) : rule;
  const escaped = body.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${escaped}${endAnchored ? "$" : ""}`);
}

export function robotsAllows(rules: RobotsRule[], pathAndQuery: string): boolean {
  let winner: RobotsRule | undefined;
  let winnerSpecificity = -1;
  for (const rule of rules) {
    if (!rule.path || !pathPattern(rule.path).test(pathAndQuery)) continue;
    const specificity = rule.path.replace(/[\*$]/g, "").length;
    if (
      specificity > winnerSpecificity ||
      (specificity === winnerSpecificity && rule.allow && !winner?.allow)
    ) {
      winner = rule;
      winnerSpecificity = specificity;
    }
  }
  return winner?.allow ?? true;
}

function parseRobots(text: string): RobotsRule[] {
  const groups: Array<{ agents: string[]; rules: RobotsRule[] }> = [];
  let group: { agents: string[]; rules: RobotsRule[] } | undefined;
  let hasRule = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split("#", 1)[0]?.trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === "user-agent") {
      if (!group || hasRule) {
        group = { agents: [], rules: [] };
        groups.push(group);
        hasRule = false;
      }
      group.agents.push(value.toLowerCase());
    } else if ((name === "allow" || name === "disallow") && group) {
      if (value) group.rules.push({ path: value, allow: name === "allow" });
      hasRule = true;
    }
  }
  const matches = groups
    .map((candidate) => ({
      ...candidate,
      score: Math.max(
        -1,
        ...candidate.agents
          .filter((agent) => agent === "*" || USER_AGENT.toLowerCase().includes(agent))
          .map((agent) => (agent === "*" ? 0 : agent.length)),
      ),
    }))
    .filter((candidate) => candidate.score >= 0);
  const best = Math.max(-1, ...matches.map((candidate) => candidate.score));
  return matches.filter((candidate) => candidate.score === best).flatMap((candidate) => candidate.rules);
}

async function cachedRobots(host: string, dataDir: string, allowedHosts: ReadonlySet<string>): Promise<RobotsSnapshot> {
  const key = host.toLowerCase();
  const inMemory = cache.get(key);
  if (inMemory && Date.now() - Date.parse(inMemory.fetched_at) < CACHE_TTL_MS) return inMemory;
  const file = join(dataDir, "policy", "robots.json");
  try {
    const persisted = JSON.parse(await readFile(file, "utf8")) as Record<string, RobotsSnapshot>;
    const snapshot = persisted[key];
    if (snapshot && Date.now() - Date.parse(snapshot.fetched_at) < CACHE_TTL_MS) {
      cache.set(key, snapshot);
      return snapshot;
    }
  } catch {
    // No cached rules: fetch a fresh public robots.txt.
  }
  let robotsUrl = `https://${key}/robots.txt`;
  let response: Response | undefined;
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    response = await fetch(robotsUrl, {
      headers: { "User-Agent": `${USER_AGENT}/1.0` },
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    if (response.status < 300 || response.status >= 400) break;
    const location = response.headers.get("location");
    const next = location ? new URL(location, robotsUrl) : undefined;
    if (!next || next.protocol !== "https:" || !allowedHosts.has(next.hostname.toLowerCase()) || redirects === 3) throw new Error("ROBOTS_REDIRECT_BLOCKED");
    robotsUrl = next.href;
  }
  if (!response) throw new Error("ROBOTS_UNAVAILABLE");
  let rules: RobotsRule[];
  if (response.status === 404 || response.status === 410) rules = [];
  else if (response.status >= 200 && response.status < 300) rules = parseRobots(await response.text());
  else throw new Error("ROBOTS_UNAVAILABLE");
  const snapshot = { rules, fetched_at: new Date().toISOString() };
  cache.set(key, snapshot);
  await mkdir(join(dataDir, "policy"), { recursive: true });
  let stored: Record<string, RobotsSnapshot> = {};
  try {
    stored = JSON.parse(await readFile(file, "utf8")) as Record<string, RobotsSnapshot>;
  } catch {
    // First cache entry.
  }
  stored[key] = snapshot;
  await writeFile(file, JSON.stringify(stored), { mode: 0o600 });
  return snapshot;
}

export async function buildRequestPolicy(hosts: readonly string[], dataDir: string): Promise<RequestPolicy> {
  const uniqueHosts = [...new Set(hosts.map((host) => host.toLowerCase()))].sort();
  const hostSet = new Set(uniqueHosts);
  const robots = Object.fromEntries(
    await Promise.all(uniqueHosts.map(async (host) => [host, (await cachedRobots(host, dataDir, hostSet)).rules] as const)),
  );
  return { allowedHosts: uniqueHosts, robots };
}

export function urlAllowed(url: string, policy: RequestPolicy): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return (
    parsed.protocol === "https:" &&
    policy.allowedHosts.includes(parsed.hostname.toLowerCase()) &&
    robotsAllows(policy.robots[parsed.hostname.toLowerCase()] ?? [], parsed.pathname + parsed.search)
  );
}
