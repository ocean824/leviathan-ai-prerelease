/** Shared lesson-19 display-label and identifier safety rules. */

const DISPLAY_LABEL_GRAMMAR = /^[A-Za-z]{1,16}[0-9]{0,3}(?:[ -][A-Za-z]{1,16}[0-9]{0,3}){0,2}$/;
const IDENTIFIER_GRAMMAR = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$/;
const LONG_DIGIT_RUN = /[0-9]{9,}/;
const LETTER_THEN_DIGITS = /^[A-Za-z]+[0-9]+$/;
const VERSION_TOKEN = /^v[0-9]{1,3}$/;
const JWT_CANDIDATE = /(?<![A-Za-z0-9])(?<header>eyJ[A-Za-z0-9_-]{1,509})\.(?<payload>[A-Za-z0-9_-]{1,8192})(?:\.(?<signature>[A-Za-z0-9_-]{0,8192}))?(?![A-Za-z0-9_-])/g;

// These bounded family patterns mirror text.credential_patterns and its
// Python parity fixture. Keep them bounded to the scanner's 64 KiB limit.
const CREDENTIAL_VALUE_PATTERNS: readonly RegExp[] = [
  /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/@:]{1,128}:[^\s/@]{1,256}@/i,
  /[?&;](?:api[_-]?key|token|secret)=[^&#;\s]{1,65536}/i,
  /\bsk_(?:live|test)_[A-Za-z0-9_-]{4,65536}\b/i,
  /\bgh[pso]_[A-Za-z0-9_-]{8,65536}\b/i,
  /\bgh[ur]_[A-Za-z0-9_-]{8,65536}\b/i,
  /\bgithub_pat_[A-Za-z0-9_]{8,65536}\b/i,
  /\bxox[abpr]-[A-Za-z0-9-]{8,65536}\b/i,
  /\bsk-[A-Za-z0-9_-]{8,65536}\b/i,
  /\bglpat-[A-Za-z0-9_-]{8,65536}\b/i,
  /\bAIza[A-Za-z0-9_-]{20,65536}\b/i,
  /\bxoxe-[A-Za-z0-9-]{8,65536}\b/i,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/i,
  /\bhttps?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{16,65536}/i,
  /\bhttps?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{5,32}\/[A-Za-z0-9._-]{16,65536}/i,
  /\bhttps?:\/\/hooks\.[A-Za-z0-9.-]{1,253}\/(?:services|webhooks|hooks)\/[A-Za-z0-9/_-]{16,65536}/i,
  /\b(?:password|passwd)\s{0,16}[:=]\s{0,16}[^\s,;]{1,65536}/i,
  /\b(?:cookie|set-cookie|authorization)\s{0,16}[:=]\s{0,16}[^\r\n]{1,65536}/i,
  /\bbearer\s{1,16}[A-Za-z0-9._~+/=-]{8,65536}/i,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/i,
  /\bpypi-[A-Za-z0-9_-]{8,65536}\b/i,
];

// Keep this policy table in sync with leviathan_core.text.safe_label.
const LESSON_19_DENY_WORDS = new Set([
  "api", "auth", "authorization", "bearer", "cert", "certificate", "cookie",
  "credential", "credentials", "ghp", "jwt", "key", "mnemonic", "password", "passwd",
  "pem", "private", "secret", "secrets", "session", "signature", "signing", "sk",
  "ssh", "token", "tokens", "wallet",
]);
const LESSON_19_SECRET_PREFIXES = ["sk_", "ghp_", "gho_", "ghr_", "ghs_", "ghu_", "xox", "akia", "ya29."];
const LESSON_19_COMPOUND_DENY_WORDS = new Set([
  "apikey", "apikeyprod", "api_key", "api_key_prod", "authcenter", "bearerplan", "mysecret", "mysecretkey", "my_secret",
  "password", "pass_word", "passwd", "pass_wd", "passwdvault",
]);

function containsJwtShape(value: string): boolean {
  if (!value.includes("eyJ")) return false;
  const decodeJsonSegment = (encoded: string): unknown => {
    const base64 = encoded.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=");
    const binary = atob(base64);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  };
  for (const match of value.matchAll(JWT_CANDIDATE)) {
    const groups = match.groups;
    if (!groups) continue;
    let payload: unknown;
    try {
      payload = decodeJsonSegment(groups.payload);
    } catch {
      continue;
    }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) continue;
    let header: unknown;
    try {
      header = decodeJsonSegment(groups.header);
    } catch {
      if (groups.signature !== undefined && groups.signature.length >= 8) return true;
      continue;
    }
    if (
      header !== null &&
      typeof header === "object" &&
      !Array.isArray(header) &&
      "alg" in header &&
      typeof header.alg === "string" &&
      header.alg.length > 0
    ) {
      return true;
    }
  }
  return false;
}

function containsCredentialValue(value: string): boolean {
  if (value.length > 65_536) return true;
  return containsJwtShape(value) || CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(value));
}

function containsIdentifierCredential(value: string): boolean {
  const separators = "_-.:/";
  for (let index = 0; index < value.length; index += 1) {
    if (
      (index === 0 || separators.includes(value[index - 1] ?? "")) &&
      containsCredentialValue(value.slice(index))
    ) {
      return true;
    }
  }
  return false;
}

function safeText(
  value: string,
  rejectLetterDigitTokens: boolean,
  stripDisplaySuffixDigits = false,
): boolean {
  if (LONG_DIGIT_RUN.test(value)) return false;
  const normalized = value.toLowerCase();
  const segments = normalized.split(/[ -]/).filter(Boolean);
  const deniedSegments = stripDisplaySuffixDigits
    ? segments.map((segment) => segment.replace(/[0-9]{1,3}$/, ""))
    : segments;
  if (deniedSegments.some((segment) =>
    LESSON_19_DENY_WORDS.has(segment) || LESSON_19_COMPOUND_DENY_WORDS.has(segment),
  )) return false;
  if (LESSON_19_SECRET_PREFIXES.some((prefix) =>
    normalized.startsWith(prefix) || [..." .:/_-"].some((separator) => normalized.startsWith(separator + prefix)),
  )) {
    return false;
  }
  if (rejectLetterDigitTokens && segments.some((segment) =>
    LETTER_THEN_DIGITS.test(segment) && !VERSION_TOKEN.test(segment),
  )) {
    return false;
  }
  return !containsCredentialValue(value);
}

export function isSafeDisplayLabel(value: unknown): value is string {
  return typeof value === "string" && value.length <= 40 && DISPLAY_LABEL_GRAMMAR.test(value) &&
    safeText(value, false, true);
}

export function isSafeIdentifier(value: unknown): value is string {
  return typeof value === "string" && IDENTIFIER_GRAMMAR.test(value) &&
    !containsIdentifierCredential(value) && safeText(value, true);
}
