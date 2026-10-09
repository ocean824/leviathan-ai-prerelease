export type RouteClassV1 = "TRIANGULAR" | "CROSS_DEX" | "CEX_DEX";
export type AtomicityV1 = "ATOMIC" | "NON_ATOMIC";
export type MevRiskV1 = "LOW" | "MEDIUM" | "HIGH";
export type RouteAgeBucketV1 = "FRESH" | "AMBER" | "STALE";
export type RouteDisplayStatusV1 =
  | "VIABLE"
  | "RISK_LOCKED"
  | "STALE"
  | "FLASH_INELIGIBLE"
  | "NO_LIQUIDITY";

export type RouteReasonCodeV1 =
  | "CEX_DEX"
  | "LOCK_GAS_LIMIT"
  | "LOCK_MAX_NOTIONAL"
  | "LOCK_RATE_LIMIT"
  | "LOCK_SLIPPAGE_LIMIT"
  | "LOCK_TIME_WINDOW"
  | "LOCK_TOKEN_BLOCKLIST"
  | "LOCK_VENUE_BLOCKLIST"
  | "MEV_HIGH_PRIVATE_RELAY_REQUIRED"
  | "NO_LIQUIDITY"
  | "NON_ATOMIC"
  | "STALE_DATA";

export interface RouteHopV1 {
  readonly venue_id: string;
  readonly token_in: string;
  readonly token_out: string;
}

/** Typed UI projection of the integrated FLA-ROUTE-VM-001 RouteViewV1. */
export interface RouteViewV1 {
  readonly route_id: string;
  readonly route_class: RouteClassV1;
  readonly atomicity: AtomicityV1;
  readonly chain_id: string;
  readonly base_token: string;
  readonly quote_token: string;
  readonly hops: readonly RouteHopV1[];
  readonly venues: readonly string[];
  readonly net_profit: string;
  readonly spread_bps: string;
  readonly gas_cost: string;
  readonly loan_size: string;
  readonly slippage_headroom_bps: string;
  readonly latency_eta_ms: number;
  /** Nanosecond integers cross the JS view boundary as bigint to preserve precision. */
  readonly event_time_ns: bigint;
  readonly age_ns: bigint;
  readonly age_ms: bigint;
  readonly age_bucket: RouteAgeBucketV1;
  readonly mev_risk: MevRiskV1;
  readonly private_relay_enabled: boolean;
  readonly liquidity_available: boolean;
  readonly status: RouteDisplayStatusV1;
  readonly reason_codes: readonly RouteReasonCodeV1[];
  readonly read_only: true;
}

export interface FlashLoanRoutesViewProps {
  /** Ordered synthetic or locally supplied view-model rows; this component never fetches. */
  readonly routes: readonly RouteViewV1[];
  /** Current monotonic/source clock in nanoseconds, injected by the caller. */
  readonly clock: () => bigint;
}
