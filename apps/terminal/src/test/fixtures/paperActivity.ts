/** Synthetic PAPER-only OMS responses for independent acceptance tests. */

export const PAPER_ACTIVITY_PATH = "/api/orders/activity";
export const ORDER_STATUS_PATH = "/api/orders/status";
export const RISK_STATUS_PATH = "/api/risk/status";

export const paperActivityResponse = {
  schema_version: 1,
  evidence_label: "OMS ledger evidence",
  environment: "paper",
  account_id: "paper-account-acceptance",
  high_water_sequence: 12,
  items: [
    {
      kind: "ORDER",
      ledger_sequence: 10,
      order: {
        order_id: "paper-order-001",
        venue: "SYNTHETIC",
        instrument_id: "SYNTH-01",
        side: "BUY",
        state: "PARTIALLY_FILLED",
        quantity: "2",
        filled_quantity: "1.25",
        discrepancies: ["FILL_CORRECTION"],
        created_at_utc: "2026-10-06T15:00:00Z",
      },
    },
    {
      kind: "FILL",
      ledger_sequence: 11,
      fill: {
        order_id: "paper-order-001",
        execution_id: "paper-exec-001",
        venue: "SYNTHETIC",
        instrument_id: "SYNTH-01",
        side: "BUY",
        quantity: "1.25",
        price: "100.25",
        commission: "0.01",
        occurred_at_utc: "2026-10-06T15:01:00Z",
      },
    },
    {
      kind: "FILL_CORRECTION",
      ledger_sequence: 12,
      correction: {
        order_id: "paper-order-001",
        execution_id: "paper-exec-001",
        correction_id: "paper-correction-001",
        revision: 2,
        revised_quantity: "1",
        revised_price: "100.25",
        revised_commission: "0.01",
        occurred_at_utc: "2026-10-06T15:02:00Z",
      },
    },
  ],
  next_cursor: null,
  net_filled_units: [
    { venue: "SYNTHETIC", instrument_id: "SYNTH-01", quantity: "-1.23" },
  ],
  // Unknown free-text fields must never become rendered operator content.
  operator_note: "LESSON19_FREE_TEXT_CANARY",
  raw_payload: { secret: "LESSON19_SECRET_CANARY" },
};

export const paperOrderStatus = {
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 0,
  as_of: "2026-10-06T15:03:00Z",
  raw_payload: "ORDER_STATUS_RAW_CANARY",
};

export const haltedPaperRiskStatus = {
  halted: true,
  active_halts: ["operator_halt"],
  operating_mode: "paper",
  fault_code: null,
  policy: { max_daily_dd_pct: "2.00" },
  as_of: "2026-10-06T15:03:00Z",
  raw_payload: "RISK_STATUS_RAW_CANARY",
};

export const paperActivityUnavailable = {
  error: { code: "PAPER_ACTIVITY_UNAVAILABLE" },
};
