export type GoogleIdentityErrorCodeV1 =
  | "MALFORMED_ID_TOKEN"
  | "GOOGLE_KEY_UNAVAILABLE"
  | "INVALID_GOOGLE_SIGNATURE"
  | "INVALID_GOOGLE_CLAIMS";

export class GoogleIdentityErrorV1 extends Error {
  constructor(readonly code: GoogleIdentityErrorCodeV1) {
    super(code);
    this.name = "GoogleIdentityErrorV1";
  }
}

export interface GoogleIdentityV1 {
  readonly subject: string;
  readonly email: string;
  readonly email_verified: true;
  readonly name: string | null;
  readonly picture: string | null;
}

export interface GoogleRsaJwkV1 extends JsonWebKey {
  readonly kid: string;
}

export interface GoogleJwksV1 {
  readonly keys: readonly GoogleRsaJwkV1[];
}

export interface GoogleTokenVerificationOptionsV1 {
  readonly audience: string;
  readonly nonce?: string;
  /** Compare against a hash when the transaction store deliberately retains no raw nonce. */
  readonly nonce_sha256?: string;
  readonly now_unix_seconds: number;
  readonly fetcher?: typeof fetch;
  readonly crypto_api?: Crypto;
}

const GOOGLE_ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);
const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const EMAIL = /^[^\s@]{1,128}@[^\s@.]{1,63}(?:\.[^\s@.]{1,63})+$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function decodeBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > 16_384) return null;
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}

function safeName(value: unknown): string | null {
  return typeof value === "string" && value.length <= 256 && !CONTROL.test(value) ? value : null;
}

function safePicture(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 2048) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && (url.hostname === "googleusercontent.com"
      || url.hostname.endsWith(".googleusercontent.com")) ? url.toString() : null;
  } catch {
    return null;
  }
}

async function readGoogleJwks(fetcher: typeof fetch): Promise<GoogleJwksV1> {
  let response: Response;
  try {
    response = await fetcher(GOOGLE_JWKS_URL, { method: "GET", redirect: "error" });
  } catch {
    throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  }
  if (!response.ok) throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  let text: string;
  try {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("body unavailable");
    const chunks: Uint8Array[] = []; let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > 128_000) { await reader.cancel(); throw new Error("body too large"); }
      chunks.push(part.value);
    }
    const bytes = new Uint8Array(total); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  }
  if (!isRecord(value) || !Array.isArray(value.keys) || value.keys.length > 32) {
    throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  }
  const keys = value.keys.filter((item): item is GoogleRsaJwkV1 => isRecord(item)
    && item.kty === "RSA" && typeof item.kid === "string" && item.kid.length <= 256
    && (item.alg === undefined || item.alg === "RS256")
    && (item.use === undefined || item.use === "sig")
    && typeof item.n === "string" && item.n.length <= 2048
    && typeof item.e === "string" && item.e === "AQAB"
    && !["d", "p", "q", "dp", "dq", "qi", "oth"].some((name) => name in item));
  return Object.freeze({ keys: Object.freeze(keys) });
}

function validAudience(claim: unknown, authorizedParty: unknown, expected: string): boolean {
  if (claim === expected) return authorizedParty === undefined || authorizedParty === expected;
  if (!Array.isArray(claim) || !claim.every((item) => typeof item === "string")
      || !claim.includes(expected)) return false;
  return authorizedParty === expected;
}

export async function verifyGoogleIdentityTokenV1(
  token: string,
  options: GoogleTokenVerificationOptionsV1,
): Promise<GoogleIdentityV1> {
  if (typeof token !== "string" || token.length > 32_768 || token.split(".").length !== 3
      || typeof options.audience !== "string" || options.audience.length < 8
      || ((options.nonce === undefined) === (options.nonce_sha256 === undefined))
      || (options.nonce !== undefined && (typeof options.nonce !== "string" || options.nonce.length < 16))
      || (options.nonce_sha256 !== undefined && !/^[0-9a-f]{64}$/.test(options.nonce_sha256))
      || !Number.isSafeInteger(options.now_unix_seconds) || options.now_unix_seconds < 0) {
    throw new GoogleIdentityErrorV1("MALFORMED_ID_TOKEN");
  }

  const parts = token.split(".");
  const headerBytes = decodeBase64Url(parts[0]!);
  const claimsBytes = decodeBase64Url(parts[1]!);
  const signature = decodeBase64Url(parts[2]!);
  if (!headerBytes || !claimsBytes || !signature) {
    throw new GoogleIdentityErrorV1("MALFORMED_ID_TOKEN");
  }

  let header: unknown;
  let claims: unknown;
  try {
    header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(headerBytes)) as unknown;
    claims = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(claimsBytes)) as unknown;
  } catch {
    throw new GoogleIdentityErrorV1("MALFORMED_ID_TOKEN");
  }
  if (!isRecord(header) || header.alg !== "RS256" || typeof header.kid !== "string"
      || !isRecord(claims)) throw new GoogleIdentityErrorV1("MALFORMED_ID_TOKEN");

  const fetcher = options.fetcher ?? fetch;
  const jwks = await readGoogleJwks(fetcher);
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk) throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");

  let key: CryptoKey;
  try {
    key = await (options.crypto_api ?? globalThis.crypto).subtle.importKey(
      "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"],
    );
  } catch {
    throw new GoogleIdentityErrorV1("GOOGLE_KEY_UNAVAILABLE");
  }
  const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
  let verified = false;
  try {
    verified = await (options.crypto_api ?? globalThis.crypto).subtle.verify(
      "RSASSA-PKCS1-v1_5", key, buffer(signature), buffer(signingInput),
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new GoogleIdentityErrorV1("INVALID_GOOGLE_SIGNATURE");

  const now = options.now_unix_seconds;
  const exp = claims.exp;
  let nonceValid = false;
  if (typeof claims.nonce === "string" && claims.nonce.length >= 16 && claims.nonce.length <= 256) {
    if (options.nonce !== undefined) nonceValid = claims.nonce === options.nonce;
    else {
      const digest = new Uint8Array(await (options.crypto_api ?? globalThis.crypto).subtle.digest(
        "SHA-256", new TextEncoder().encode(claims.nonce),
      ));
      const actual = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
      nonceValid = actual === options.nonce_sha256;
    }
  }
  const iat = claims.iat;
  if (typeof claims.iss !== "string" || !GOOGLE_ISSUERS.has(claims.iss)
      || !validAudience(claims.aud, claims.azp, options.audience)
      || typeof exp !== "number" || !Number.isSafeInteger(exp) || exp <= now
      || typeof iat !== "number" || !Number.isSafeInteger(iat) || iat > now + 60
      || exp <= iat || exp - iat > 3600
      || !nonceValid
      || claims.email_verified !== true
      || typeof claims.sub !== "string" || claims.sub.length < 1 || claims.sub.length > 255
      || CONTROL.test(claims.sub)
      || typeof claims.email !== "string" || claims.email.length > 254 || !EMAIL.test(claims.email)) {
    throw new GoogleIdentityErrorV1("INVALID_GOOGLE_CLAIMS");
  }

  return Object.freeze({
    subject: claims.sub,
    email: claims.email.toLowerCase(),
    email_verified: true,
    name: safeName(claims.name),
    picture: safePicture(claims.picture),
  });
}

export interface PkcePairV1 {
  readonly verifier: string;
  readonly challenge: string;
}

function base64Url(bytes: Uint8Array): string {
  let raw = "";
  for (const value of bytes) raw += String.fromCharCode(value);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function createPkcePairV1(cryptoApi: Crypto = globalThis.crypto): Promise<PkcePairV1> {
  const random = cryptoApi.getRandomValues(new Uint8Array(32));
  const verifier = base64Url(random);
  const digest = await cryptoApi.subtle.digest("SHA-256", buffer(new TextEncoder().encode(verifier)));
  const challenge = base64Url(new Uint8Array(digest));
  return Object.freeze({ verifier, challenge });
}

export function googleAuthorizationUrlV1(input: {
  readonly client_id: string;
  readonly redirect_uri: string;
  readonly state: string;
  readonly nonce: string;
  readonly code_challenge: string;
}): string {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", input.client_id);
  url.searchParams.set("redirect_uri", input.redirect_uri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.code_challenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}
