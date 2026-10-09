/** Synthetic endpoint payloads for LIVE-GUARD-UI-001 acceptance tests. */

export const RAW_PAYLOAD_CANARY = "raw-payload-canary-DO-NOT-RENDER";

export const riskStatusWithGateCodes = {
  halted: true,
  active_halts: ["operator_hold", "omega_kill_signal"],
  fault_code: "HALT_STORE_UNAVAILABLE",
  operating_mode: "paper",
  policy: {
    max_daily_dd_pct: "17.25",
    max_open_heat_pct: "23.75",
    consensus_threshold: 0.91,
  },
  lock_file: `C:/private/${RAW_PAYLOAD_CANARY}`,
  raw_payload: RAW_PAYLOAD_CANARY,
};

export const ordersStatusWithGateCodes = {
  live_enabled: false,
  recovery_status: "FAILED",
  activation_count: 7,
  raw_payload: RAW_PAYLOAD_CANARY,
};

export const ordersStatusClaimingLiveEnabled = {
  ...ordersStatusWithGateCodes,
  live_enabled: true,
};

export const riskStatusWithUnknownGateCodes = {
  ...riskStatusWithGateCodes,
  active_halts: [RAW_PAYLOAD_CANARY, "CODE_SHAPED_ATTACK"],
  fault_code: "ATTACKER_SUPPLIED_FAULT",
};

export const ordersStatusWithUnknownRecovery = {
  ...ordersStatusWithGateCodes,
  recovery_status: "ATTACKER_SUPPLIED_RECOVERY",
};

export const STATIC_HALT_CODES = [
  "omega_kill_signal",
  "operator_halt",
  "operator_hold",
  "risk_limit_breach",
  "stale_data",
  "reconciliation_divergence",
  "audit_sink_failure",
  "tiamat_hash_mismatch",
  "daily_drawdown_breach",
  "weekly_drawdown_breach",
  "trailing_drawdown_breach",
  "legacy_state_unknown",
] as const;

export const OMEGA_HALT_PREFIXES = [
  "omega_kill",
  "omega_bridge_disconnected",
  "omega_bridge_degraded",
] as const;

export const OMEGA_HALT_HASHES = ["a".repeat(64), "b".repeat(64), "c".repeat(64)] as const;

export const NEAR_MISS_HALT_CODES = [
  `omega_kill:${"A".repeat(64)}`,
  `omega_kill:${"a".repeat(63)}`,
  `omega_kill:${"a".repeat(65)}`,
  `omega_kill:${"a".repeat(64)}:extra`,
  "omega_kill:",
  "omega_kill",
  `omega_unknown:${"a".repeat(64)}`,
  `OMEGA_KILL:${"a".repeat(64)}`,
  ` omega_kill:${"a".repeat(64)}`,
  `omega_kill: ${"a".repeat(64)}`,
  `omega_kill_signal:${"a".repeat(64)}`,
] as const;

export function riskStatusForHaltCodes(codes: readonly string[]) {
  return {
    ...riskStatusWithGateCodes,
    halted: true,
    active_halts: [...codes],
    fault_code: null,
    operating_mode: "research",
  };
}

export const malformedRiskStatus = {
  halted: RAW_PAYLOAD_CANARY,
  active_halts: RAW_PAYLOAD_CANARY,
  fault_code: { payload: RAW_PAYLOAD_CANARY },
  operating_mode: [RAW_PAYLOAD_CANARY],
  policy: RAW_PAYLOAD_CANARY,
};

export const rawFailurePayload = {
  detail: `SECRET raw response body ${RAW_PAYLOAD_CANARY}`,
};
