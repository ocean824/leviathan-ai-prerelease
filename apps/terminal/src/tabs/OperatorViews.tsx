import { useEffect, useState } from "react";
import { PanelCard } from "../components/PanelCard";
import { evaluatePanelState, freshPanel, OPERATOR_STALE_MS, unavailablePanel } from "../state/panelState";
import type { Clock, PanelState } from "../state/panelState";
import type { FilterKey } from "../navigation/commands";

export type FilterState = Partial<Record<FilterKey, string>>;
type ViewName = "TODAY" | "SYMBOL" | "STRATEGY";
type PanelSpec = { title: string; reason: string; eyebrow: string };
const PANEL_SPECS: Record<ViewName, PanelSpec[]> = {
  TODAY: [
    { title: "Top Flow / DP", eyebrow: "01 / MARKET ACTIVITY", reason: "Flow and dark-pool feed is not connected." },
    { title: "Regime", eyebrow: "02 / CONTEXT", reason: "Regime model output is not connected." },
    { title: "Earnings / IV", eyebrow: "03 / EVENTS", reason: "Earnings and implied-volatility feed is not connected." },
  ],
  SYMBOL: [
    { title: "Levels", eyebrow: "01 / PRICE STRUCTURE", reason: "No timestamped levels are available for this symbol." },
    { title: "Flow / DP", eyebrow: "02 / PARTICIPATION", reason: "Flow and dark-pool feed is not connected." },
    { title: "IV", eyebrow: "03 / OPTIONS", reason: "Implied-volatility feed is not connected." },
    { title: "Catalysts", eyebrow: "04 / EVENTS", reason: "Catalyst feed is not connected." },
  ],
  STRATEGY: [
    { title: "Active Plays", eyebrow: "01 / PORTFOLIO", reason: "Strategy activity feed is not connected." },
    { title: "Edge Health", eyebrow: "02 / HEALTH", reason: "No audited Edge Health inputs are available." },
    { title: "Obsidian Updates", eyebrow: "03 / KNOWLEDGE", reason: "Obsidian sync and audit services are unavailable." },
  ],
};
const TITLES: Record<ViewName, { title: string; subtitle: string; number: string }> = {
  TODAY: { title: "Today", subtitle: "A clear view of the session, with source integrity at every step.", number: "01 / 03" },
  SYMBOL: { title: "Symbol intelligence", subtitle: "One instrument, one context. Market levels appear only with sourced data.", number: "02 / 03" },
  STRATEGY: { title: "Strategy workspace", subtitle: "Research state and action readiness in one deliberate view.", number: "03 / 03" },
};

function useTime(clock: Clock) {
  const [now, setNow] = useState(clock());
  useEffect(() => {
    const id = window.setInterval(() => setNow(clock()), 250);
    return () => window.clearInterval(id);
  }, [clock]);
  return now;
}

function OperatorView({ view, symbol, filters, fixture, clock = Date.now }: {
  view: ViewName; symbol: string | null; filters: FilterState; fixture: "healthy" | "stale" | null; clock?: Clock;
}) {
  const now = useTime(clock);
  const [mountedAt] = useState(clock);
  const meta = TITLES[view];
  const filtered = Object.entries(filters);
  function stateFor(spec: PanelSpec): PanelState<{ records: number }> {
    if (!fixture) return unavailablePanel("Gateway API", spec.reason);
    const asOf = mountedAt - (fixture === "stale" ? OPERATOR_STALE_MS + 1_000 : 0);
    const sourceState = freshPanel({ records: 0 }, "Fixture", asOf, () => mountedAt);
    return evaluatePanelState(sourceState, () => now, OPERATOR_STALE_MS);
  }

  return <div className={`operator-view operator-view--${view.toLowerCase()}`}>
    <div className="view-intro operator-view__intro">
      <div className="eyebrow">OPERATOR WORKSPACE <span>/ {meta.number}</span></div>
      <div className="view-intro__title"><h2>{meta.title}</h2><span className="view-code">{view}</span></div>
      <p>{meta.subtitle}</p>
    </div>
    <div className="context-ribbon">
      <div><span className="context-ribbon__label">DATA MODE</span><strong>{fixture ? "Fixture — local sample packet" : "Disconnected — no market feed"}</strong></div>
      <div><span className="context-ribbon__label">SYMBOL CONTEXT</span><strong>{symbol ?? "No symbol selected"}</strong></div>
      <div><span className="context-ribbon__label">FILTERS</span><strong>{filtered.length ? filtered.map(([key, value]) => `${key}=${value}`).join(" · ") : "None"}</strong></div>
    </div>
    {view === "SYMBOL" && <div className="notice">{symbol ? `${symbol} selected. Quote, level and flow data are unavailable until a sourced feed is connected.` : "Enter /sym <ticker> to select a symbol. No quote is available."}</div>}
    <div className="operator-section-heading"><span>INTELLIGENCE PANELS</span><span>{String(PANEL_SPECS[view].length).padStart(2, "0")} MODULES</span></div>
    <div className="operator-grid">{PANEL_SPECS[view].map((spec) => <PanelCard key={spec.title}
      title={spec.title} eyebrow={spec.eyebrow} state={stateFor(spec)}
      renderData={(data) => <div className="fixture-content"><strong>Packet received</strong><span>{data.records} market records supplied. No market value is asserted.</span></div>} />)}</div>
    {view === "STRATEGY" && <section className="action-lock"><div><div className="eyebrow">CONTROL PLANE / LOCKED</div><h3>Obsidian actions</h3>
      <p>Role, MFA and audit services must be available before updates can be submitted.</p></div>
      <button type="button" disabled title="Role, MFA and audit services unavailable">Submit update · unavailable</button></section>}
    <div className="view-footnote">SOURCE DISCIPLINE <span>Timestamped packets only · fixture data is never live · no execution from this shell</span></div>
  </div>;
}

export function Today(props: Omit<Parameters<typeof OperatorView>[0], "view">) { return <OperatorView view="TODAY" {...props} />; }
export function Symbol(props: Omit<Parameters<typeof OperatorView>[0], "view">) { return <OperatorView view="SYMBOL" {...props} />; }
export function Strategy(props: Omit<Parameters<typeof OperatorView>[0], "view">) { return <OperatorView view="STRATEGY" {...props} />; }
