import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent, UIEvent } from "react";
import { isSafeIdentifier } from "../shared/safeLabel";
import type {
  FlashLoanRoutesViewProps,
  RouteReasonCodeV1,
  RouteViewV1,
} from "./FlashLoanRoutesTypes";

const VIEWPORT_HEIGHT = 480;
const ROW_HEIGHT = 160;
const OVERSCAN_ROWS = 3;
const CLOCK_REFRESH_MS = 250;
const FRESH_CUTOFF_NS = 250_000_000n;
const AMBER_CUTOFF_NS = 750_000_000n;
const DECIMAL_PATTERN = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
const REASON_LABELS: Record<RouteReasonCodeV1, string> = {
  CEX_DEX: "Centralized exchange and decentralized exchange routes cannot use a flash loan",
  LOCK_GAS_LIMIT: "Gas limit lock is active",
  LOCK_MAX_NOTIONAL: "Maximum notional lock is active",
  LOCK_RATE_LIMIT: "Rate limit lock is active",
  LOCK_SLIPPAGE_LIMIT: "Slippage limit lock is active",
  LOCK_TIME_WINDOW: "Time window lock is active",
  LOCK_TOKEN_BLOCKLIST: "Token blocklist lock is active",
  LOCK_VENUE_BLOCKLIST: "Venue blocklist lock is active",
  MEV_HIGH_PRIVATE_RELAY_REQUIRED: "High MEV requires a private relay",
  NO_LIQUIDITY: "Liquidity is unavailable",
  NON_ATOMIC: "Route is not atomic and cannot use a flash loan",
  STALE_DATA: "Route data is stale",
};

function safeClock(clock: () => bigint): bigint | null {
  try {
    const value: unknown = clock();
    return typeof value === "bigint" && value >= 0n ? value : null;
  } catch {
    return null;
  }
}

function safeLabel(value: unknown): string {
  return isSafeIdentifier(value) ? value : "Unlisted value";
}

function decimalLabel(value: unknown): string {
  return typeof value === "string" && value.length <= 128 && DECIMAL_PATTERN.test(value)
    ? value
    : "Unverified";
}

function routeStatusLabel(route: RouteViewV1): string {
  if (route.route_class === "CEX_DEX" || route.status === "FLASH_INELIGIBLE") {
    return "Flash Ineligible";
  }
  switch (route.status) {
    case "VIABLE": return "Viable";
    case "RISK_LOCKED": return "Risk Locked";
    case "STALE": return "Stale";
    case "NO_LIQUIDITY": return "No Liquidity";
    default: return "Unknown";
  }
}

function mevRiskLabel(value: unknown): string {
  switch (value) {
    case "LOW": return "Low";
    case "MEDIUM": return "Medium";
    case "HIGH": return "High";
    default: return "Unverified";
  }
}

function eventAge(nowNs: bigint | null, eventTimeNs: bigint): bigint | null {
  if (nowNs === null || typeof eventTimeNs !== "bigint" || eventTimeNs < 0n || nowNs < eventTimeNs) {
    return null;
  }
  return nowNs - eventTimeNs;
}

function ageBucket(ageNs: bigint | null): string {
  if (ageNs === null) return "UNVERIFIED";
  if (ageNs < FRESH_CUTOFF_NS) return "FRESH";
  if (ageNs <= AMBER_CUTOFF_NS) return "AMBER";
  return "STALE";
}

function formatAge(ageNs: bigint | null): string {
  if (ageNs === null) return "Unavailable";
  if (ageNs < 1_000_000_000n) return `${ageNs / 1_000_000n} ms`;
  const seconds = ageNs / 1_000_000_000n;
  const centiseconds = (ageNs % 1_000_000_000n) / 10_000_000n;
  if (seconds < 60n) return `${seconds}.${centiseconds.toString().padStart(2, "0")} s`;
  const minutes = seconds / 60n;
  return `${minutes} min ${seconds % 60n} s`;
}

function reasonText(code: unknown): string {
  if (typeof code !== "string" || !Object.hasOwn(REASON_LABELS, code)) return "Unknown restriction";
  const knownCode = code as RouteReasonCodeV1;
  return `${knownCode}: ${REASON_LABELS[knownCode]}`;
}

function RouteRow({
  route,
  index,
  count,
  active,
  nowNs,
  rowRef,
  onKeyDown,
}: {
  route: RouteViewV1;
  index: number;
  count: number;
  active: boolean;
  nowNs: bigint | null;
  rowRef: (element: HTMLDivElement | null) => void;
  onKeyDown: (event: KeyboardEvent<HTMLDivElement>, index: number) => void;
}) {
  const routeName = safeLabel(route.route_id);
  const status = routeStatusLabel(route);
  const age = eventAge(nowNs, route.event_time_ns);
  const bucket = ageBucket(age);
  const reasons = route.reason_codes.map(reasonText);

  return (
    <div
      ref={rowRef}
      id={`flash-loan-route-${index}`}
      className="flash-loan-routes__row"
      role="listitem"
      aria-label={`Route ${routeName}; ${status}`}
      aria-posinset={index + 1}
      aria-setsize={count}
      tabIndex={active ? 0 : -1}
      onKeyDown={(event) => onKeyDown(event, index)}
      style={{
        boxSizing: "border-box",
        height: ROW_HEIGHT,
        overflow: "hidden",
        padding: "0.75rem",
        borderBottom: "1px solid var(--border-subtle, #39404b)",
      }}
    >
      <div className="flash-loan-routes__row-heading">
        <strong>{routeName}</strong>
        <span role="status" aria-label={`Route status: ${status}`}>{status}</span>
        <span role="status" aria-label={`Event-time data age: ${formatAge(age)}; ${bucket}`}>
          Data age: {formatAge(age)} ({bucket})
        </span>
      </div>
      <dl className="flash-loan-routes__facts">
        <div><dt>Chain</dt><dd>{safeLabel(route.chain_id)}</dd></div>
        <div><dt>Pair</dt><dd>{safeLabel(route.base_token)} / {safeLabel(route.quote_token)}</dd></div>
        <div><dt>Net profit</dt><dd>{decimalLabel(route.net_profit)}</dd></div>
        <div><dt>Gas cost</dt><dd>{decimalLabel(route.gas_cost)}</dd></div>
        <div><dt>Latency estimate</dt><dd>{Number.isSafeInteger(route.latency_eta_ms) && route.latency_eta_ms >= 0 ? `${route.latency_eta_ms} ms` : "Unverified"}</dd></div>
        <div><dt>MEV risk</dt><dd>{mevRiskLabel(route.mev_risk)}</dd></div>
        <div><dt>Liquidity</dt><dd>{route.liquidity_available ? "Available (reported)" : "Unavailable (reported)"}</dd></div>
      </dl>
      <div className="flash-loan-routes__reasons" aria-label={`Reasons for ${routeName}`}>
        {reasons.length === 0
          ? <span>No restriction reported.</span>
          : reasons.map((label, reasonIndex) => <span key={`${label}-${reasonIndex}`}>{label}</span>)}
      </div>
      <div className="flash-loan-routes__actions">
        <button type="button" disabled aria-label={`Execute ${routeName}`}>Execute</button>
        <button type="button" disabled aria-label={`Override ${routeName}`}>Override</button>
      </div>
    </div>
  );
}

/** Read-only, virtualized route view. It has no network or action surface. */
export function FlashLoanRoutesView({ routes, clock }: FlashLoanRoutesViewProps) {
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const rowRefs = useRef(new Map<number, HTMLDivElement>());
  const focusAfterRender = useRef(false);
  const [scrollTop, setScrollTop] = useState(0);
  const [activeIndex, setActiveIndex] = useState(0);
  const [nowNs, setNowNs] = useState<bigint | null>(() => safeClock(clock));

  useEffect(() => {
    const timer = window.setInterval(() => setNowNs(safeClock(clock)), CLOCK_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [clock]);

  const firstVisible = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN_ROWS);
  const lastVisible = Math.min(
    routes.length,
    Math.ceil((scrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) + OVERSCAN_ROWS,
  );
  const visibleRoutes = routes.slice(firstVisible, lastVisible);

  useEffect(() => {
    if (!focusAfterRender.current) return;
    rowRefs.current.get(activeIndex)?.focus();
    focusAfterRender.current = false;
  }, [activeIndex, firstVisible, lastVisible]);

  function handleScroll(event: UIEvent<HTMLDivElement>) {
    const nextScrollTop = event.currentTarget.scrollTop;
    setScrollTop(nextScrollTop);
    const first = Math.max(0, Math.floor(nextScrollTop / ROW_HEIGHT));
    const last = Math.min(routes.length - 1, Math.ceil((nextScrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) - 1);
    if (routes.length > 0 && (activeIndex < first || activeIndex > last)) setActiveIndex(first);
  }

  function handleRowKeyDown(event: KeyboardEvent<HTMLDivElement>, index: number) {
    let nextIndex: number | null = null;
    if (event.key === "ArrowDown") nextIndex = Math.min(routes.length - 1, index + 1);
    if (event.key === "ArrowUp") nextIndex = Math.max(0, index - 1);
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = routes.length - 1;
    if (nextIndex === null || nextIndex === index) return;
    event.preventDefault();
    focusAfterRender.current = true;
    setActiveIndex(nextIndex);
    const viewport = viewportRef.current;
    if (viewport !== null) {
      const rowTop = nextIndex * ROW_HEIGHT;
      const rowBottom = rowTop + ROW_HEIGHT;
      if (rowTop < viewport.scrollTop) viewport.scrollTop = rowTop;
      else if (rowBottom > viewport.scrollTop + VIEWPORT_HEIGHT) {
        viewport.scrollTop = rowBottom - VIEWPORT_HEIGHT;
      }
      setScrollTop(viewport.scrollTop);
    }
  }

  return (
    <div className="tab-content">
      <section className="panel flash-loan-routes" aria-labelledby="flash-loan-routes-heading">
        <h2 id="flash-loan-routes-heading" className="panel__heading">Flash-loan routes</h2>
        <section className="operator-panel" aria-label="LIVE status">
          <div className="operator-panel__heading">
            <h3>LIVE</h3>
            <span role="status" aria-label="LIVE trading status: DISABLED">DISABLED</span>
          </div>
          <p>Read-only route display. LIVE remains disabled.</p>
        </section>
        <p role="note">Performance and update SLA: UNVERIFIED.</p>
        <div
          ref={viewportRef}
          className="flash-loan-routes__viewport"
          data-testid="flash-loan-routes-viewport"
          role="list"
          aria-label="Flash loan routes"
          onScroll={handleScroll}
          style={{ height: VIEWPORT_HEIGHT, overflowY: "auto", position: "relative" }}
        >
          <div aria-hidden="true" style={{ height: firstVisible * ROW_HEIGHT }} />
          {visibleRoutes.map((route, offset) => {
            const index = firstVisible + offset;
            return (
              <RouteRow
                key={route.route_id}
                route={route}
                index={index}
                count={routes.length}
                active={index === activeIndex}
                nowNs={nowNs}
                rowRef={(element) => {
                  if (element === null) rowRefs.current.delete(index);
                  else rowRefs.current.set(index, element);
                }}
                onKeyDown={handleRowKeyDown}
              />
            );
          })}
          <div aria-hidden="true" style={{ height: Math.max(0, routes.length - lastVisible) * ROW_HEIGHT }} />
        </div>
        {routes.length === 0 && <p role="status">No routes are available.</p>}
      </section>
    </div>
  );
}
