function toBuffer(bytes: Uint8Array): ArrayBuffer {
  const value = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(value).set(bytes);
  return value;
}

function toBase64Url(bytes: Uint8Array): string {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64 + "=".repeat((4 - base64.length % 4) % 4));
    return Uint8Array.from(raw, (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}

function decodeSecret(value: string): Uint8Array | null {
  if (typeof value !== "string" || value.length > 256) return null;
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const bytes = Uint8Array.from(atob(normalized + "=".repeat((4 - normalized.length % 4) % 4)),
      (character) => character.charCodeAt(0));
    return bytes.length === 32 ? bytes : null;
  } catch {
    return null;
  }
}

async function deriveKey(secret: string, cryptoApi: Crypto): Promise<CryptoKey> {
  const raw = decodeSecret(secret);
  if (!raw) throw new TypeError("OAUTH_STATE_KEY_UNAVAILABLE");
  const material = await cryptoApi.subtle.importKey("raw", toBuffer(raw), "HKDF", false, ["deriveKey"]);
  return cryptoApi.subtle.deriveKey({
    name: "HKDF",
    hash: "SHA-256",
    salt: toBuffer(new TextEncoder().encode("leviathan-auth-google-001-pkce-v1")),
    info: toBuffer(new TextEncoder().encode("web-pkce-verifier-encryption")),
  }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

export async function encryptWebPkceVerifierV1(
  verifier: string,
  stateHash: string,
  encryptionKeyBase64: string,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<string> {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(verifier) || !/^[0-9a-f]{64}$/.test(stateHash)) {
    throw new TypeError("INVALID_PKCE_STATE");
  }
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(encryptionKeyBase64, cryptoApi);
  const ciphertext = new Uint8Array(await cryptoApi.subtle.encrypt({
    name: "AES-GCM",
    iv: toBuffer(iv),
    additionalData: toBuffer(new TextEncoder().encode("web-pkce:" + stateHash)),
    tagLength: 128,
  }, key, toBuffer(new TextEncoder().encode(verifier))));
  return "a256gcm$" + toBase64Url(iv) + "$" + toBase64Url(ciphertext);
}

export async function decryptWebPkceVerifierV1(
  serialized: string,
  stateHash: string,
  encryptionKeyBase64: string,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<string> {
  const parts = serialized.split("$");
  const iv = parts.length === 3 && parts[0] === "a256gcm" ? fromBase64Url(parts[1]!) : null;
  const ciphertext = parts.length === 3 ? fromBase64Url(parts[2]!) : null;
  if (!iv || iv.length !== 12 || !ciphertext || ciphertext.length < 17
      || !/^[0-9a-f]{64}$/.test(stateHash)) throw new TypeError("OAUTH_STATE_UNAVAILABLE");
  const key = await deriveKey(encryptionKeyBase64, cryptoApi);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await cryptoApi.subtle.decrypt({
      name: "AES-GCM",
      iv: toBuffer(iv),
      additionalData: toBuffer(new TextEncoder().encode("web-pkce:" + stateHash)),
      tagLength: 128,
    }, key, toBuffer(ciphertext));
  } catch {
    throw new TypeError("OAUTH_STATE_UNAVAILABLE");
  }
  const verifier = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(verifier)) throw new TypeError("OAUTH_STATE_UNAVAILABLE");
  return verifier;
}

export async function pkceChallengeV1(
  verifier: string,
  cryptoApi: Crypto = globalThis.crypto,
): Promise<string> {
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(verifier)) throw new TypeError("INVALID_PKCE_VERIFIER");
  const digest = await cryptoApi.subtle.digest("SHA-256",
    toBuffer(new TextEncoder().encode(verifier)));
  return toBase64Url(new Uint8Array(digest));
}

export function pkceVerifierMatchesV1(verifier: string, challenge: string): Promise<boolean> {
  return pkceChallengeV1(verifier).then((derived) => derived === challenge).catch(() => false);
}

function randomBase64Url(byteLength: number, cryptoApi: Crypto): string {
  return toBase64Url(cryptoApi.getRandomValues(new Uint8Array(byteLength)));
}

export interface PkcePairV1 {
  readonly verifier: string;
  readonly challenge: string;
}

export async function createPkcePairV1(cryptoApi: Crypto = globalThis.crypto): Promise<PkcePairV1> {
  const verifier = randomBase64Url(32, cryptoApi);
  return Object.freeze({ verifier, challenge: await pkceChallengeV1(verifier, cryptoApi) });
}

export function createOAuthSecretsV1(cryptoApi: Crypto = globalThis.crypto): {
  readonly state: string; readonly nonce: string;
} {
  return Object.freeze({ state: randomBase64Url(32, cryptoApi), nonce: randomBase64Url(32, cryptoApi) });
}
