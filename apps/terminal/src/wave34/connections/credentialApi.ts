export type CredentialStateV1 = {
  provider_id: string;
  environment: string;
  configured: boolean;
  verified: boolean;
  last_tested_ns: number | null;
  last_rotated_ns: number | null;
  error_code: string | null;
};

export type CredentialWriteV1 = {
  fields?: Record<string, string | number>;
  secrets?: Record<string, string>;
  confirm_environment?: "LIVE";
};

const BASE = "/api/connections/credentials";
const SAFE_ERRORS = new Set([
  "PRINCIPAL_UNTRUSTED", "CONNECTION_FORBIDDEN", "INVALID_PROVIDER", "INVALID_ENVIRONMENT",
  "INVALID_CREDENTIAL", "PROFILE_NOT_FOUND", "PROVIDER_NOT_FOUND", "LIVE_CONFIRMATION_REQUIRED",
  "REPLACE_NOT_SUPPORTED", "CONFIRMATION_REQUIRED", "CONFIRMATION_ORIGIN_DENIED", "CONFIRMATION_UNAVAILABLE",
  "LIVE_BINDING_UNAVAILABLE", "LIVE_ACTIVATION_UNAVAILABLE", "AUDIT_UNAVAILABLE",
  "CREDENTIALS_UNAVAILABLE", "TEST_UNAVAILABLE", "SECRET_UNAVAILABLE",
]);

function path(provider: string, environment: string): string {
  return `${BASE}/${encodeURIComponent(provider)}/${encodeURIComponent(environment)}/default`;
}

export function createCredentialConnectionsApi(fetcher?: typeof fetch) {
  async function request<T>(url: string, init?: RequestInit): Promise<T> {
    const response = await (fetcher ?? fetch)(url, {
      ...init,
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(init?.headers ?? {}) },
    });
    let payload: unknown;
    try { payload = await response.json(); } catch { payload = null; }
    if (!response.ok) {
      const code = typeof payload === "object" && payload !== null && "code" in payload
        ? (payload as { code?: unknown }).code : null;
      throw new Error(typeof code === "string" && SAFE_ERRORS.has(code) ? code : "CREDENTIALS_UNAVAILABLE");
    }
    return payload as T;
  }

  return {
    status: () => request<{ credentials: CredentialStateV1[] }>(BASE),
    replaceIntent: (provider: string, environment: string) =>
      request<{ intent: "OPEN_REPLACE_FORM"; provider_id: string; environment: string; profile_id: string }>(
        `${path(provider, environment)}/replace-intent`, { method: "POST" },
      ),
    replace: (provider: string, environment: string, body: CredentialWriteV1) =>
      request<CredentialStateV1>(path(provider, environment), {
        method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      }),
    test: (provider: string, environment: string) =>
      request<{ provider_id: string; verified: boolean; error_code: string | null }>(
        `${path(provider, environment)}/test`, { method: "POST" },
      ),
    remove: async (provider: string, environment: string, confirmLive = false) => {
      const confirmation = await request<{ confirmation_token: string; expires_at_ns: string }>(
        `${path(provider, environment)}/remove-confirmation`, { method: "POST" },
      );
      if (typeof confirmation.confirmation_token !== "string" ||
          !/^[A-Za-z0-9_-]{32,128}$/.test(confirmation.confirmation_token) ||
          typeof confirmation.expires_at_ns !== "string" ||
          !/^\d{1,20}$/.test(confirmation.expires_at_ns)) {
        throw new Error("CONFIRMATION_UNAVAILABLE");
      }
      return request<{ provider_id: string; removed: boolean }>(path(provider, environment), {
        method: "DELETE", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          confirmation_token: confirmation.confirmation_token,
          ...(confirmLive ? { confirm_environment: "LIVE" as const } : {}),
        }),
      });
    },
    uploadKalshiKey: async (environment: string, keyName: string, bytes: Uint8Array, confirmLive = false) => {
      const uploadBuffer = new ArrayBuffer(bytes.byteLength);
      new Uint8Array(uploadBuffer).set(bytes);
      try {
        return await request<CredentialStateV1>(`${path("kalshi", environment)}/private-key`, {
          method: "PUT", headers: {
            "Content-Type": "application/octet-stream", "X-Credential-Key-Name": keyName,
            ...(confirmLive ? { "X-Confirm-Environment": "LIVE" } : {}),
          },
          body: uploadBuffer,
        });
      } finally {
        bytes.fill(0);
        new Uint8Array(uploadBuffer).fill(0);
      }
    },
  };
}

export const credentialConnectionsApi = createCredentialConnectionsApi();
