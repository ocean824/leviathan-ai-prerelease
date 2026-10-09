import { LiveTrading } from "../../tabs/live-trading/LiveTrading";
import LiveActivationView from "./LiveActivationView";

/** Keeps the activation controls and the established credential surface together on LIVE. */
export function LiveWorkspace() {
  return <div className="live-workspace">
    <LiveActivationView />
    <LiveTrading />
  </div>;
}
