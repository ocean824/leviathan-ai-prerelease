export type ReleaseChannel = "desktop" | "admin";

export interface PlatformUpdate {
  readonly url: string;
  readonly signature: string;
}

export interface TauriUpdateManifest {
  readonly version: string;
  readonly notes: string;
  readonly pub_date: string;
  readonly platforms: Readonly<Record<string, PlatformUpdate>>;
}

export type ManifestFailureCode =
  | "INVALID_MANIFEST"
  | "SIGNATURE_MISSING"
  | "HOST_NOT_ALLOWED"
  | "NON_MONOTONIC_VERSION";

export class ManifestValidationError extends Error {
  constructor(readonly code: ManifestFailureCode) {
    super(code);
    this.name = "ManifestValidationError";
  }
}

interface ParsedVersion {
  readonly major: bigint;
  readonly minor: bigint;
  readonly patch: bigint;
  readonly prerelease: readonly string[];
}

const PLATFORM_KEY = /^[a-z0-9]+-[a-z0-9_]+$/;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const RFC3339 = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function parseVersion(value: string): ParsedVersion {
  const match = VERSION.exec(value);
  if (!match) {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }

  const prerelease = match[4]?.split(".") ?? [];
  if (prerelease.some((part) => /^[0-9]+$/.test(part) && part.length > 1 && part.startsWith("0"))) {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }

  return {
    major: BigInt(match[1]),
    minor: BigInt(match[2]),
    patch: BigInt(match[3]),
    prerelease,
  };
}

function compareNumericIdentifiers(left: string, right: string): number {
  const a = BigInt(left);
  const b = BigInt(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

export function compareSemVer(left: string, right: string): number {
  const a = parseVersion(left);
  const b = parseVersion(right);

  for (const key of ["major", "minor", "patch"] as const) {
    if (a[key] !== b[key]) {
      return a[key] < b[key] ? -1 : 1;
    }
  }

  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    if (a.prerelease.length === b.prerelease.length) return 0;
    return a.prerelease.length === 0 ? 1 : -1;
  }

  const limit = Math.min(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < limit; index += 1) {
    const leftId = a.prerelease[index];
    const rightId = b.prerelease[index];
    const leftNumeric = /^[0-9]+$/.test(leftId);
    const rightNumeric = /^[0-9]+$/.test(rightId);

    if (leftNumeric && rightNumeric) {
      const comparison = compareNumericIdentifiers(leftId, rightId);
      if (comparison !== 0) return comparison;
      continue;
    }
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    if (leftId !== rightId) return leftId < rightId ? -1 : 1;
  }

  if (a.prerelease.length === b.prerelease.length) return 0;
  return a.prerelease.length < b.prerelease.length ? -1 : 1;
}

function isValidPublicationDate(value: string): boolean {
  const match = RFC3339.exec(value);
  if (!match) return false;

  const [, yearText, monthText, dayText, hourText, minuteText, secondText, offset] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;

  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  calendar.setUTCHours(0, 0, 0, 0);
  if (calendar.getUTCFullYear() !== year || calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) {
    return false;
  }

  if (offset !== "Z") {
    const offsetHour = Number(offset.slice(1, 3));
    const offsetMinute = Number(offset.slice(4, 6));
    if (offsetHour > 23 || offsetMinute > 59) return false;
  }
  return Number.isFinite(Date.parse(value));
}

function isAllowedUrl(value: string, allowedHosts: ReadonlySet<string>): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }

  const hostname = url.hostname.toLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== "" ||
    (url.port !== "" && url.port !== "443") ||
    !HOSTNAME.test(hostname)
  ) {
    throw new ManifestValidationError("HOST_NOT_ALLOWED");
  }
  if (!allowedHosts.has(hostname)) throw new ManifestValidationError("HOST_NOT_ALLOWED");
  return true;
}

export function normalizeAllowedHosts(value: string): ReadonlySet<string> {
  const entries = value.split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean);
  if (entries.length === 0 || entries.some((host) => !HOSTNAME.test(host))) {
    throw new Error("INVALID_CONFIGURATION");
  }
  return new Set(entries);
}

export function validateTauriManifest(
  input: unknown,
  allowedHosts: ReadonlySet<string>,
): TauriUpdateManifest {
  if (!isRecord(input) || !hasExactKeys(input, ["version", "notes", "pub_date", "platforms"])) {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }
  if (typeof input.version !== "string") throw new ManifestValidationError("INVALID_MANIFEST");
  parseVersion(input.version);
  if (typeof input.notes !== "string" || typeof input.pub_date !== "string" || !isValidPublicationDate(input.pub_date)) {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }
  if (!isRecord(input.platforms) || Object.keys(input.platforms).length === 0) {
    throw new ManifestValidationError("INVALID_MANIFEST");
  }

  const platforms: Record<string, PlatformUpdate> = {};
  for (const [platform, rawUpdate] of Object.entries(input.platforms)) {
    if (!PLATFORM_KEY.test(platform) || !isRecord(rawUpdate)) {
      throw new ManifestValidationError("INVALID_MANIFEST");
    }
    if (typeof rawUpdate.signature !== "string" || rawUpdate.signature.trim().length === 0) {
      throw new ManifestValidationError("SIGNATURE_MISSING");
    }
    if (!hasExactKeys(rawUpdate, ["url", "signature"])) {
      throw new ManifestValidationError("INVALID_MANIFEST");
    }
    if (rawUpdate.signature.length > 64 * 1024 || typeof rawUpdate.url !== "string" || rawUpdate.url.length > 4096) {
      throw new ManifestValidationError("INVALID_MANIFEST");
    }
    isAllowedUrl(rawUpdate.url, allowedHosts);
    platforms[platform] = { url: rawUpdate.url, signature: rawUpdate.signature };
  }

  return {
    version: input.version,
    notes: input.notes,
    pub_date: input.pub_date,
    platforms,
  };
}
