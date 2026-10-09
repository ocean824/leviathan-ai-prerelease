import type {
  OrderMonitorOrder,
  OrderMonitorOrderState,
  OrderMonitorStatus,
} from "../../api/orderMonitor";

export const orderMonitorStatus: OrderMonitorStatus = {
  live_enabled: false,
  recovery_status: "READY",
  activation_count: 0,
};

export function orderMonitorOrder(
  state: OrderMonitorOrderState,
  overrides: Partial<OrderMonitorOrder> = {},
): OrderMonitorOrder {
  return {
    order_id: "0123456789abcdef0123456789abcdef",
    state,
    version: 3,
    environment: "paper",
    account_id: "paper-account",
    venue: "ALPACA",
    instrument_id: "AAPL",
    strategy_id: "strategy-acceptance",
    filled_quantity: "0",
    venue_order_id: "venue-order-001",
    discrepancies: [],
    submit_attempted: true,
    cancel_attempted: false,
    ...overrides,
  };
}
