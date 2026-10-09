/** LIC-001 wire data. Revisions and UTC nanosecond timestamps use decimal text. */
export type LicenseStatusV1 =
  | "ACTIVE" | "PAST_DUE" | "PAUSED"
  | "SUSPENDED" | "CANCELED" | "EXPIRED";

export interface LicenseSnapshotV1 {
  readonly schemaVersion: 1;
  readonly orgId: string;
  readonly licenseId: string;
  readonly subscriptionRevision: string;
  readonly status: LicenseStatusV1;
  readonly termStartUtcNs: string;
  readonly termEndUtcNs: string;
  readonly issuedAtUtcNs: string;
  readonly lastOnlineVerifiedUtcNs: string;
  readonly features: Readonly<Record<string, boolean>>;
  /** Nonnegative integer or exact decimal text; never a binary float. */
  readonly limits: Readonly<Record<string, string>>;
  readonly audience: string;
  readonly deviceId: string;
  readonly signingKeyId: string;
  readonly signature: Readonly<{
    algorithm: "ECDSA_P256_SHA256";
    /** Raw IEEE P1363 ECDSA signature, unpadded base64url. */
    value: string;
  }>;
}

/** Explicit policy only. LIC-001 assigns no grace capabilities. */
export interface GracePolicyV1 {
  readonly schemaVersion: 1;
  readonly maxOfflineSeconds: number;
}

export type EntitlementOutcomeV1 =
  | "VERIFIED_ONLINE" | "GRACE_OFFLINE" | "DENIED" | "UNKNOWN";

export type EntitlementReasonV1 =
  | "ONLINE_ACTIVE" | "POSITIVE_CACHE" | "OFFLINE_GRACE"
  | "GRACE_POLICY_MISSING" | "GRACE_EXPIRED"
  | "INVALID_INPUT" | "INVALID_SNAPSHOT" | "INVALID_SIGNATURE"
  | "TRUST_KEY_UNAVAILABLE" | "BINDING_MISMATCH"
  | "REVISION_ROLLBACK" | "CLOCK_ROLLBACK"
  | "TERM_INVALID" | "TERM_EXPIRED" | "LICENSE_INACTIVE"
  | "CACHE_UNAVAILABLE" | "CACHE_CORRUPT" | "ONLINE_ANCHOR_STALE";

export interface EntitlementDecisionV1 {
  readonly schemaVersion: 1;
  readonly outcome: EntitlementOutcomeV1;
  readonly reason: EntitlementReasonV1;
  /** End of this decision's time window, if any; UTC nanoseconds. */
  readonly expiresAtUtcNs: string | null;
  /** True only for a verified active online license. Other policy gates still apply. */
  readonly authorizesGatedEffects: boolean;
}

/** Opaque, process-local state. It cannot be serialized into a trusted cache. */
export interface EntitlementStateV1 {
  readonly schemaVersion: 1;
}

export interface EntitlementInputV1 {
  readonly mode: "ONLINE" | "OFFLINE";
  /** Required for ONLINE; ignored for OFFLINE, which uses prior trusted state. */
  readonly snapshot?: LicenseSnapshotV1;
  readonly state?: EntitlementStateV1;
  readonly expectedOrgId: string;
  readonly expectedAudience: string;
  readonly expectedDeviceId: string;
  readonly signingKeys: ReadonlyMap<string, CryptoKey>;
  /** Injected monotonic clock reading. A process restart starts a new state. */
  readonly nowMonotonicMs: number;
  /** Injected wall reading checked against signed and prior UTC anchors. */
  readonly nowWallUtcNs: string;
  readonly gracePolicy?: GracePolicyV1;
}

export interface EntitlementResultV1 {
  readonly decision: EntitlementDecisionV1;
  readonly state: EntitlementStateV1;
}
