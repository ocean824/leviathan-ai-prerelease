import {
  compareSemVer,
  normalizeAllowedHosts,
  validateTauriManifest,
} from "./manifest.js";
import type { ReleaseChannel } from "./manifest.js";

export interface R2TextObjectPort {
  readonly size?: number;
  readonly customMetadata?: Readonly<Record<string, string>>;
  text(): Promise<string>;
}

export interface R2ReadPort {
  get(key: string): Promise<R2TextObjectPort | null>;
}

export interface ClockPort {
  now(): Date;
}

export interface ReleaseFeedDependencies {
  readonly releases: R2ReadPort;
  readonly now: ClockPort;
  readonly allowedArtifactHosts: readonly string[];
  readonly cacheTtlSeconds: number;
  readonly recordEvent?: (event: "FEED_BEHIND_CLIENT") => void;
}

interface UpdateRequest {
  readonly channel: ReleaseChannel;
  readonly target: string;
  readonly arch: string;
  readonly currentVersion: string;
}

const CHANNELS = new Set<ReleaseChannel>(["desktop", "admin"]);
const TARGET = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ARCH = /^[a-z0-9]+(?:[_-][a-z0-9]+)*$/;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_CACHE_TTL_SECONDS = 300;

function errorResponse(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: { code } }), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function invalidFeedResponse(): Response {
  return new Response(null, {
    status: 503,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Leviathan-Error": "FEED_INVALID",
    },
  });
}

function readUpdateRequest(request: Request): UpdateRequest | Response {
  if (request.method !== "GET") {
    return new Response(null, {
      status: 405,
      headers: { Allow: "GET", "Cache-Control": "no-store" },
    });
  }

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return errorResponse(400, "INVALID_REQUEST");
  }
  if (url.search !== "") return errorResponse(400, "INVALID_REQUEST");

  const parts = url.pathname.split("/");
  if (parts.length !== 7 || parts[0] !== "" || parts[1] !== "v1" || parts[2] !== "updates") {
    return errorResponse(404, "NOT_FOUND");
  }

  const [, , , rawChannel, target, arch, currentVersion] = parts;
  if (!CHANNELS.has(rawChannel as ReleaseChannel)) return errorResponse(404, "NOT_FOUND");
  if (!TARGET.test(target) || !ARCH.test(arch)) return errorResponse(400, "INVALID_REQUEST");

  return {
    channel: rawChannel as ReleaseChannel,
    target,
    arch,
    currentVersion,
  };
}

function cacheHeaders(deps: ReleaseFeedDependencies): Headers | null {
  if (
    !Number.isSafeInteger(deps.cacheTtlSeconds) ||
    deps.cacheTtlSeconds < 1 ||
    deps.cacheTtlSeconds > MAX_CACHE_TTL_SECONDS
  ) {
    return null;
  }

  const now = deps.now.now();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) return null;

  const expires = new Date(now.getTime() + deps.cacheTtlSeconds * 1000).toUTCString();
  return new Headers({
    "Cache-Control": `public, max-age=${deps.cacheTtlSeconds}, s-maxage=${deps.cacheTtlSeconds}, must-revalidate`,
    Expires: expires,
    "X-Content-Type-Options": "nosniff",
  });
}

function emptyUpdate(headers: Headers): Response {
  return new Response(null, { status: 204, headers });
}

export function createReleaseFeedHandler(
  deps: ReleaseFeedDependencies,
): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    const parsed = readUpdateRequest(request);
    if (parsed instanceof Response) return parsed;

    let allowedHosts: ReadonlySet<string>;
    try {
      allowedHosts = normalizeAllowedHosts(deps.allowedArtifactHosts.join(","));
    } catch {
      return errorResponse(503, "CONFIGURATION_ERROR");
    }

    const headers = cacheHeaders(deps);
    if (!headers) return errorResponse(503, "CONFIGURATION_ERROR");

    try {
      compareSemVer(parsed.currentVersion, parsed.currentVersion);
    } catch {
      return errorResponse(400, "INVALID_VERSION");
    }

    const objectKey = `channels/${parsed.channel}/latest.json`;
    let object: R2TextObjectPort | null;
    try {
      object = await deps.releases.get(objectKey);
    } catch {
      return errorResponse(503, "RELEASE_STORE_UNAVAILABLE");
    }
    if (object === null) return emptyUpdate(headers);
    if (object.customMetadata?.channel !== undefined && object.customMetadata.channel !== parsed.channel) {
      return invalidFeedResponse();
    }
    if (object.size !== undefined && object.size > MAX_MANIFEST_BYTES) {
      return invalidFeedResponse();
    }

    let source: string;
    try {
      source = await object.text();
    } catch {
      return errorResponse(503, "RELEASE_STORE_UNAVAILABLE");
    }
    if (new TextEncoder().encode(source).byteLength > MAX_MANIFEST_BYTES) {
      return invalidFeedResponse();
    }

    let input: unknown;
    try {
      input = JSON.parse(source) as unknown;
    } catch {
      return invalidFeedResponse();
    }

    let manifest;
    try {
      manifest = validateTauriManifest(input, allowedHosts);
    } catch {
      return invalidFeedResponse();
    }

    let comparison: number;
    try {
      comparison = compareSemVer(manifest.version, parsed.currentVersion);
    } catch {
      return errorResponse(400, "INVALID_VERSION");
    }
    if (comparison === 0) {
      headers.set("X-Leviathan-Feed", "no-newer");
      return emptyUpdate(headers);
    }
    if (comparison < 0) {
      try {
        if (deps.recordEvent) deps.recordEvent("FEED_BEHIND_CLIENT");
        else console.info("FEED_BEHIND_CLIENT");
      } catch {
        // Observability must not alter the updater response.
      }
      headers.set("X-Leviathan-Feed", "no-newer");
      return emptyUpdate(headers);
    }

    const platform = `${parsed.target}-${parsed.arch}`;
    if (!manifest.platforms[platform]) return emptyUpdate(headers);

    headers.set("Content-Type", "application/json; charset=utf-8");
    return new Response(JSON.stringify(manifest), { status: 200, headers });
  };
}

export interface CloudflareReleaseFeedEnv {
  readonly RELEASES: R2ReadPort;
  readonly ALLOWED_ARTIFACT_HOSTS: string;
  readonly MANIFEST_CACHE_TTL_SECONDS: string;
}

function parseConfiguredTtl(value: string): number | null {
  if (!/^[1-9][0-9]*$/.test(value)) return null;
  const ttl = Number(value);
  if (!Number.isSafeInteger(ttl) || ttl > MAX_CACHE_TTL_SECONDS) return null;
  return ttl;
}

const systemClock: ClockPort = { now: () => new Date() };

const worker = {
  fetch(request: Request, env: CloudflareReleaseFeedEnv): Promise<Response> {
    const ttl = parseConfiguredTtl(env.MANIFEST_CACHE_TTL_SECONDS);
    if (ttl === null) return Promise.resolve(errorResponse(503, "CONFIGURATION_ERROR"));

    const handler = createReleaseFeedHandler({
      releases: env.RELEASES,
      now: systemClock,
      allowedArtifactHosts: env.ALLOWED_ARTIFACT_HOSTS.split(","),
      cacheTtlSeconds: ttl,
    });
    return handler(request);
  },
};

export default worker;
