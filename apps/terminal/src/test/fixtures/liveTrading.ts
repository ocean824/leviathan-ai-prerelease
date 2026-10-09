export const credentialFixture = {
  endpoint: "/api/live-trading/credentials",
  profilePath: "/api/live-trading/credentials/ALPACA/PAPER/default",
  liveProfilePath: "/api/live-trading/credentials/ALPACA/LIVE/default",
  secrets: {
    keyId: "SYNTHETIC-ALPACA-KEY-DO-NOT-STORE-001",
    secretKey: "SYNTHETIC-ALPACA-SECRET-DO-NOT-STORE-002",
    liveKeyId: "SYNTHETIC-LIVE-KEY-DO-NOT-STORE-003",
    liveSecretKey: "SYNTHETIC-LIVE-SECRET-DO-NOT-STORE-004",
  },
  responseMarkers: {
    statusSecret: "SYNTHETIC-STATUS-SECRET-NEVER-RENDER-005",
    statusToken: "SYNTHETIC-STATUS-TOKEN-NEVER-RENDER-006",
    unexpected: "SYNTHETIC-RESPONSE-FIELD-NEVER-RENDER-007",
    writeProfile: "SYNTHETIC-PUT-PROFILE-NEVER-RENDER-008",
    writeValue: "SYNTHETIC-PUT-VALUE-NEVER-RENDER-009",
    errorDetail: "SYNTHETIC-ERROR-DETAIL-NEVER-RENDER-010",
  },
} as const;

export function credentialStatusResponse() {
  return {
    profiles: [
      {
        provider: "ALPACA",
        environment: "PAPER",
        profile: "default",
        configured: { key_id: true, secret_key: true },
        updated_at: "2026-10-06T12:00:00Z",
        verification: "VERIFIED",
        status: "CONNECTED",
        key_id: credentialFixture.responseMarkers.statusSecret,
        secret_key: credentialFixture.responseMarkers.statusSecret,
        token: credentialFixture.responseMarkers.statusToken,
        secret_length: 64,
        secret_prefix: "SYNTHETIC",
        secret_suffix: "MARKER",
        secret_sha256: credentialFixture.responseMarkers.unexpected,
      },
    ],
    unexpected_secret: credentialFixture.responseMarkers.statusSecret,
    response_value: credentialFixture.responseMarkers.unexpected,
  };
}

export function credentialWriteResponse() {
  return {
    provider: "RESPONSE-PROVIDER-MARKER",
    environment: "RESPONSE-ENVIRONMENT-MARKER",
    profile: credentialFixture.responseMarkers.writeProfile,
    revision: 87654321,
    configured: { secret_key: true },
    updated_at: "1999-01-01T00:00:00Z",
    verification: "VERIFIED",
    status: "CONNECTED",
    secret_value: credentialFixture.responseMarkers.writeValue,
  };
}

export function credentialErrorResponse() {
  return {
    code: "SYNTHETIC-ERROR-CODE",
    detail: credentialFixture.responseMarkers.errorDetail,
    received_secret: credentialFixture.secrets.secretKey,
  };
}
