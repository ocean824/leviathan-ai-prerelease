import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import "./App.css";
import "./workstation.css";
import { CommandBar } from "./components/CommandBar";
import { WorkspaceTabs } from "./components/WorkspaceTabs";
import { StreamHealthPanel } from "./components/StreamHealthPanel";
import { resolveHash, REGISTRY } from "./navigation/registry";
import type { NavigationCode } from "./navigation/registry";
import type { ParsedCommand } from "./navigation/commands";
import { CommandCenter } from "./tabs/CommandCenter";
import { Journal } from "./tabs/Journal";
import { Risk } from "./tabs/Risk";
import { Genomes } from "./tabs/Genomes";
import { Pipeline } from "./tabs/Pipeline";
import { Help } from "./tabs/Help";
import { Today, Symbol, Strategy } from "./tabs/OperatorViews";
import type { FilterState } from "./tabs/OperatorViews";
import { KnowledgeArchiveView } from "./wave26/views/KnowledgeArchiveView";
import { LiveGuardView } from "./wave26/views/LiveGuardView";
import { OrderMonitorView } from "./wave26/views/OrderMonitorView";
import { EaTemplateCatalogView } from "./wave26/views/EaTemplateCatalogView";
import { PaperActivityView } from "./wave28/views/PaperActivityView";
import { PaperActivationView } from "./wave27/views/PaperActivationView";
import { FlashLoanRoutesView } from "./wave30/FlashLoanRoutesView";
import type { RouteViewV1 } from "./wave30/FlashLoanRoutesTypes";
import { DataSourcesView } from "./wave34/dataSources/DataSourcesView";
import PaperOrderTicketView from "./wave33/paperOrderTicket/PaperOrderTicketView";
import { ConnectionsView } from "./wave34/connections/ConnectionsView";
import { createConnectionsApi } from "./wave34/connections/api";
import { createExternalUrlOpener } from "./platform/externalUrlOpener";
import { AppearanceSettings } from "./settings/AppearanceSettings";
import {
  isAppearancePreferenceV1,
  type PreferencesPort,
  type VersionedAppearancePreferenceV1,
} from "./settings/appearanceClient";
import {
  createPreferencesClient,
  PreferencesConflictError,
  PreferencesHttpError,
  type JsonValue,
  type UserPreferencesV1,
} from "./settings/preferencesClient";
import { ChatTerminal } from "./chat/ChatTerminal";
import { createChatClientsV1 } from "./chat/chatClient";
import type { ChatAuthStateV1 } from "./chat/chatTypes";
import { LiveWorkspace } from "./wave36/liveActivation/LiveWorkspace";

const EMPTY_FLASH_LOAN_ROUTES: readonly RouteViewV1[] = [];
const terminalClockNs = () => BigInt(Date.now()) * 1_000_000n;
const LiveMarketDataWorkspace = lazy(() => import("./wave34/charts/LiveMarketDataWorkspace")
  .then(({ LiveMarketDataWorkspace: workspace }) => ({ default: workspace })));
const connectionsExternalUrlOpener = createExternalUrlOpener();
const appConnectionsApi = createConnectionsApi((input, init) => globalThis.fetch(input, init));
const preferencesClient = createPreferencesClient({
  fetchImpl: (input, init) => globalThis.fetch(input, init),
});
const appearancePreferencesPort: PreferencesPort = {
  async read(namespace) {
    try {
      const record = await preferencesClient.get(namespace);
      const appearance = versionedAppearanceFromPreferenceRecord(record);
      return appearance ? { status: "fresh", record: appearance } : { status: "offline" };
    } catch (error) {
      if (error instanceof PreferencesHttpError && error.status === 404) {
        return { status: "fresh", record: null };
      }
      return { status: "offline" };
    }
  },
  async write(namespace, preference, expectedRevision) {
    const numericRevision = expectedRevision === null ? NaN : Number(expectedRevision);
    const revision = Number.isSafeInteger(numericRevision) && numericRevision >= 0
      ? numericRevision
      : "*";
    try {
      const record = await preferencesClient.put(
        namespace,
        preference as unknown as Record<string, JsonValue>,
        revision,
      );
      const appearance = versionedAppearanceFromPreferenceRecord(record);
      return appearance ? { status: "saved", record: appearance } : { status: "offline" };
    } catch (error) {
      if (error instanceof PreferencesConflictError) {
        return {
          status: "conflict",
          current: error.current ? versionedAppearanceFromPreferenceRecord(error.current) : null,
        };
      }
      return { status: "offline" };
    }
  },
};
const chatClients = createChatClientsV1((input, init) => globalThis.fetch(input, init));
interface ChatSessionPort {
  readonly authState: ChatAuthStateV1;
  readonly accountScopeKey: string;
}
const chatSession: ChatSessionPort = {
  authState: "unavailable",
  accountScopeKey: "unauthenticated",
};

function versionedAppearanceFromPreferenceRecord(
  record: UserPreferencesV1,
): VersionedAppearancePreferenceV1 | null {
  if (record.namespace !== "appearance" || !isAppearancePreferenceV1(record.document)) return null;
  return {
    preference: record.document,
    revision: String(record.revision),
    updated_at_ns: record.updated_at_ns,
  };
}

function ChartsWorkspace() {
  return <Suspense fallback={<section aria-label="Charts" role="status">Loading chart view.</section>}>
    <LiveMarketDataWorkspace />
  </Suspense>;
}

function PaperOrderTicketWorkspace() {
  return <section aria-label="Paper order ticket workspace">
    <div className="view-intro">
      <div className="eyebrow">PAPER / ORDER ENTRY</div>
      <h2>Paper Order Ticket</h2>
      <p role="status">Ticket unavailable. The paper activation API does not expose a current scope read, so operator trust and active scope cannot be verified.</p>
    </div>
    <PaperOrderTicketView
      trustedOperator={false}
      activePaperScope={null}
      instrument={{ native_contract_id: "", contract_multiplier: "", currency: "" }}
      priceEvidence={{ price: "", price_source_ns: 0, price_ingest_ns: 0, price_source_id: "" }}
    />
  </section>;
}

function ConnectionsWorkspace() {
  return <ConnectionsView api={appConnectionsApi} externalUrlOpener={connectionsExternalUrlOpener} />;
}

function ChatWorkspace() {
  return <ChatTerminal
    accountScopeKey={chatSession.accountScopeKey}
    authState={chatSession.authState}
    chatPort={chatClients.chatPort}
    historyPort={chatClients.historyPort}
    toolsPort={chatClients.toolsPort}
  />;
}

function FutureWorkspace({ code }: { code: NavigationCode }) {
  const entry = REGISTRY.find((item) => item.code === code)!;
  return <div className="operator-view">
    <div className="view-intro operator-view__intro"><div className="eyebrow">WORKSTATION / {code}</div>
      <div className="view-intro__title"><h2>{entry.label}</h2><span className="view-code">{code}</span></div>
      <p>{entry.description}</p></div>
    <div className="context-ribbon"><div><span className="context-ribbon__label">SOURCE</span><strong>Gateway API</strong></div>
      <div><span className="context-ribbon__label">STATUS</span><strong>Unavailable</strong></div>
      <div><span className="context-ribbon__label">AS OF</span><strong>Unavailable</strong></div></div>
    <div className="future-empty"><span className="future-empty__glyph">◇</span><div className="eyebrow">NO VERIFIED FEED</div>
      <h3>{entry.label} is not connected</h3><p>No timestamped source is wired to this workspace. Market values and controls will appear only when their data and permission services are verified.</p>
      <span className="future-empty__tag">SOURCE / UNAVAILABLE</span></div>
    {(code === "OMON" || code === "WEI") && <div className="action-lock"><div><div className="eyebrow">EXECUTION / DISABLED</div>
      <h3>Operator control unavailable</h3><p>Authentication, role enforcement and execution gates are not connected.</p></div>
      <button type="button" disabled title="Authentication and role enforcement unavailable">Action unavailable</button></div>}
  </div>;
}

export default function App() {
  const [route, setRoute] = useState(() => resolveHash(window.location.hash));
  const [symbol, setSymbol] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>({});
  const requestedFixture = new URLSearchParams(window.location.search).get("fixture");
  const fixture = requestedFixture === "healthy" || requestedFixture === "stale" ? requestedFixture : null;

  useEffect(() => {
    const onHashChange = () => setRoute(resolveHash(window.location.hash));
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  const navigate = useCallback((code: NavigationCode) => {
    setRoute({ code });
    window.location.hash = code;
  }, []);

  const onCommand = useCallback((command: ParsedCommand) => {
    if (command.type === "navigate") navigate(command.code);
    if (command.type === "symbol") { setSymbol(command.symbol); navigate("SYMBOL"); }
    if (command.type === "filter") setFilters((current) => ({ ...current, [command.key]: command.value }));
  }, [navigate]);

  function activeContent() {
    switch (route.code) {
      case "CC": return <><div className="view-intro cc-intro"><div className="eyebrow">CONTROL DESK / 00</div>
        <div className="view-intro__title"><h2>Command center</h2><span className="view-code">CC</span></div>
        <p>Start with context. Every market panel identifies its source and time.</p></div>
        <div className="entry-grid">{(["TODAY", "SYMBOL", "STRATEGY"] as const).map((code, index) => <button key={code}
          className="entry-card" type="button" onClick={() => navigate(code)}><span>0{index + 1} / OPERATOR VIEW</span>
          <strong>{code === "TODAY" ? "Today's brief" : code === "SYMBOL" ? "Symbol lens" : "Strategy desk"}</strong>
          <small>{code === "TODAY" ? "Flow · Regime · Events" : code === "SYMBOL" ? "Levels · Flow · IV" : "Active Plays · Edge Health"}</small><em>↗</em></button>)}</div>
        <div className="cc-section-title"><span>GATEWAY & CONTROL</span><span>API REPORTED · NO SOURCE TIMESTAMP</span></div>
        <CommandCenter /><StreamHealthPanel fixture={fixture} /></>;
      case "JRNL": return <Journal />;
      case "RISK": return <Risk />;
      case "GENOME": return <Genomes />;
      case "LIVE": return <LiveWorkspace />;
      case "KNOW": return <KnowledgeArchiveView />;
      case "LGD": return <LiveGuardView />;
      case "OMON": return <OrderMonitorView />;
      case "PACT": return <PaperActivityView fetcher={fetch} clock={Date.now} />;
      case "PAPR": return <PaperActivationView fetcher={fetch} clock={Date.now} />;
      case "EAC": return <EaTemplateCatalogView />;
      case "FLR": return <FlashLoanRoutesView routes={EMPTY_FLASH_LOAN_ROUTES} clock={terminalClockNs} />;
      case "DATA": return <DataSourcesView />;
      case "CHRT": return <ChartsWorkspace />;
      case "PORD": return <PaperOrderTicketWorkspace />;
      case "CONN": return <ConnectionsWorkspace />;
      case "APPR": return <AppearanceSettings preferencesPort={appearancePreferencesPort} />;
      case "CHAT": return <ChatWorkspace />;
      case "PIPE": return <Pipeline />;
      case "HELP": return <Help reason={route.reason} />;
      case "TODAY": return <Today symbol={symbol} filters={filters} fixture={fixture} />;
      case "SYMBOL": return <Symbol symbol={symbol} filters={filters} fixture={fixture} />;
      case "STRATEGY": return <Strategy symbol={symbol} filters={filters} fixture={fixture} />;
      default: return <FutureWorkspace code={route.code} />;
    }
  }

  return <main className="terminal-shell">
    <header className="terminal-header"><div className="brand-lockup"><div className="brand-mark" aria-hidden="true">Λ</div>
      <div><div className="brand-kicker">BLACK WEALTH CAPITAL / OPERATIONS</div><h1>LEVIATHAN<span> AI</span></h1></div></div>
      <div className="header-meta"><span>OPERATOR WORKSTATION</span><strong>OFFLINE FIRST <i aria-hidden="true">◆</i></strong></div></header>
    <div className="system-strip"><span><b className="system-strip__indicator" /> DATA CONNECTION <strong>{fixture ? "FIXTURE MODE" : "UNVERIFIED"}</strong></span>
      <span>MARKET CLOCK <strong>UNAVAILABLE</strong></span><span>EXECUTION <strong>DISABLED</strong></span></div>
    <CommandBar onCommand={onCommand} />
    <WorkspaceTabs active={route.code} onSelect={navigate} />
    <div className="workspace" id="active-workspace" role="tabpanel" aria-label={`${route.code} workspace`}
      aria-labelledby={REGISTRY.find((item) => item.code === route.code)?.kind === "tab" ? `tab-${route.code}` : undefined}>
      {activeContent()}
    </div>
    <footer className="terminal-footer"><span>LEVIATHAN AI <b>/</b> OPERATOR WORKSTATION</span>
      <span>DATA INTEGRITY FIRST <b>·</b> NO LIVE ORDERS</span><span>CTRL+K COMMAND</span></footer>
  </main>;
}
