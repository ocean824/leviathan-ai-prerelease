import type { ReactNode } from "react";
import { GatewayProvenance } from "../../components/GatewayProvenance";
import { GatewayStateNotice } from "../../components/GatewayStateNotice";
import { PanelCard } from "../../components/PanelCard";
import { unavailablePanel } from "../../state/panelState";
import { useGatewaySnapshot } from "../../state/useGatewaySnapshot";
import type { GatewaySnapshot } from "../../state/useGatewaySnapshot";
import { fetchOrderGuard, fetchRiskGuard } from "../api/liveGuard";
import type { OrderGuardReport, RiskGuardReport } from "../api/liveGuard";

export const LIVE_DISABLED_REASON = "operator switch and risk limits required";

/** Hard-coded. It reads no API field, so no loading, error or payload state can change it. */
function LiveStateTile() {
  return (
    <section className="operator-panel" aria-label="LIVE trading state">
      <div className="operator-panel__heading">
        <h3>LIVE</h3>
        <span className="chip chip--error chip--lg" data-testid="live-state">DISABLED</span>
      </div>
      <p>Reason: {LIVE_DISABLED_REASON}.</p>
      <p className="muted">
        This view is read-only. Nothing here can enable, arm or change live trading.
      </p>
    </section>
  );
}

function RiskReport({ report }: { report: RiskGuardReport }) {
  const haltIndicated = report.haltedReported || report.haltCodes.length > 0
    || report.faultCode !== null;
  return (
    <dl className="live-guard__report" aria-label="API-reported risk status">
      <dt>Halt state (API-reported)</dt>
      <dd>
        {haltIndicated
          ? <span className="chip chip--error">HALT INDICATED</span>
          : "No halt reported"}
      </dd>
      <dt>Halt reason codes (API-reported)</dt>
      <dd>{report.haltCodes.length === 0 ? "None reported" : report.haltCodes.join(", ")}</dd>
      <dt>Fault code (API-reported)</dt>
      <dd>{report.faultCode ?? "None reported"}</dd>
      <dt>Operating mode (API-reported)</dt>
      <dd>{report.operatingMode}</dd>
      <dt>Risk policy (API-reported)</dt>
      <dd>{report.policyReported ? "Reported; values are not shown here" : "Not reported"}</dd>
    </dl>
  );
}

function OrderReport({ report }: { report: OrderGuardReport }) {
  return (
    <dl className="live-guard__report" aria-label="API-reported order gateway status">
      <dt>Recovery status (API-reported)</dt>
      <dd>{report.recoveryStatus}</dd>
      <dt>Activation count (API-reported)</dt>
      <dd>{report.activationCount}</dd>
      {report.liveEnabledReported && (
        <>
          <dt>Inconsistency</dt>
          <dd>
            <span className="chip chip--warn">API REPORTED live_enabled TRUE</span>{" "}
            Ignored: LIVE stays DISABLED in this view.
          </dd>
        </>
      )}
    </dl>
  );
}

function GuardSection<T>({
  title,
  eyebrow,
  snapshot,
  report,
}: {
  title: string;
  eyebrow: string;
  snapshot: GatewaySnapshot<T>;
  report: (data: T) => ReactNode;
}) {
  const { panel, data } = snapshot;
  // A source timestamp outside the freshness window never keeps the values on screen.
  const shown = panel.status === "stale"
    ? unavailablePanel<T>(panel.source, "Source timestamp is outside the freshness window; values are hidden.")
    : panel;
  return (
    <div className="live-guard__section">
      <PanelCard title={title} eyebrow={eyebrow} state={shown} renderData={report} />
      {panel.status === "unavailable" && data !== null && (
        <section aria-label={`${title}: unverified API report`} className="live-guard__unverified">
          <span className="chip chip--warn">UNVERIFIED</span>
          <p>
            API-reported values with no source timestamp. The response receipt time below is
            not source time.
          </p>
          {report(data)}
        </section>
      )}
      <GatewayStateNotice {...snapshot} state={panel} />
      <GatewayProvenance {...snapshot} state={panel} />
    </div>
  );
}

export function LiveGuardView() {
  const risk = useGatewaySnapshot(fetchRiskGuard);
  const orders = useGatewaySnapshot(fetchOrderGuard);
  return (
    <div className="tab-content">
      <section className="panel" aria-label="Live Guard">
        <h2 className="panel__heading">Live Guard</h2>
        <LiveStateTile />
        <GuardSection
          title="Risk status"
          eyebrow="RISK"
          snapshot={risk}
          report={(data: RiskGuardReport) => <RiskReport report={data} />}
        />
        <GuardSection
          title="Order gateway status"
          eyebrow="ORDERS"
          snapshot={orders}
          report={(data: OrderGuardReport) => <OrderReport report={data} />}
        />
      </section>
    </div>
  );
}
