import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createPaperAccountSnapshotClient,
  PAPER_ACCOUNT_STALE_AFTER_MS,
} from "./api";
import type {
  PaperAccountSnapshotClient,
  PaperAccountSnapshotError,
  PaperAccountSnapshotV1,
} from "./api";

const ERROR_TEXT: Record<PaperAccountSnapshotError, string> = {
  INVALID_ACCOUNT_ID: "The selected account is unavailable.",
  NETWORK_UNAVAILABLE: "The account service could not be reached.",
  OPERATOR_SESSION_UNAVAILABLE: "The operator session is unavailable.",
  PAPER_SCOPE_REQUIRED: "The selected paper account is unavailable.",
  PAPER_ACCOUNT_SNAPSHOT_UNAVAILABLE: "The account snapshot is unavailable.",
  HTTP_ERROR: "The account service returned an unavailable response.",
  INVALID_RESPONSE: "The account response could not be verified.",
};

type SnapshotState =
  | { state: "loading"; data?: undefined }
  | { state: "unavailable"; error: PaperAccountSnapshotError; data?: undefined }
  | { state: "ready"; data: PaperAccountSnapshotV1 }
  | { state: "stale"; data: PaperAccountSnapshotV1; error?: PaperAccountSnapshotError };

export interface PaperAccountViewProps {
  accountId: string;
  fetcher?: typeof fetch;
  clock?: () => number;
}

function snapshotIsStale(snapshot: PaperAccountSnapshotV1, nowMs: number): boolean {
  const observedAtMs = Date.parse(snapshot.broker_observed_at);
  const ageMs = nowMs - observedAtMs;
  return !Number.isFinite(nowMs) || ageMs < 0 || ageMs > PAPER_ACCOUNT_STALE_AFTER_MS;
}

function statusBanner(state: SnapshotState) {
  if (state.state === "loading") {
    return <p role="status">Loading paper account snapshot…</p>;
  }
  if (state.state === "unavailable") {
    return <div role="alert" style={{ borderLeft: "4px solid #b42318", padding: "0.75rem", background: "#fff1f0" }}>
      <strong>UNAVAILABLE</strong> — {ERROR_TEXT[state.error]}
    </div>;
  }
  if (state.state === "stale") {
    const detail = state.error
      ? `Refresh failed. ${ERROR_TEXT[state.error]}`
      : "The broker snapshot is older than five minutes or has a future source timestamp.";
    return <div role="alert" style={{ borderLeft: "4px solid #b54708", padding: "0.75rem", background: "#fffaeb" }}>
      <strong>STALE</strong> — Showing the last broker snapshot. {detail}
    </div>;
  }
  return <p role="status">Current broker snapshot</p>;
}

export function PaperAccountView({
  accountId,
  fetcher = fetch,
  clock = Date.now,
}: PaperAccountViewProps) {
  const client: PaperAccountSnapshotClient = useMemo(
    () => createPaperAccountSnapshotClient(fetcher),
    [fetcher],
  );
  const [snapshot, setSnapshot] = useState<SnapshotState>({ state: "loading" });
  const [nowMs, setNowMs] = useState(() => clock());
  const [refreshing, setRefreshing] = useState(false);
  const latestRead = useRef(0);

  const refresh = useCallback(async () => {
    const generation = ++latestRead.current;
    setSnapshot((previous) => previous.state === "ready" || previous.state === "stale"
      ? previous.data.account_id === accountId
        ? previous
        : { state: "loading" }
      : previous);
    setRefreshing(true);
    const result = await client.getSnapshot(accountId);
    if (generation !== latestRead.current) return;
    const currentTime = clock();
    setNowMs(currentTime);
    setRefreshing(false);
    if (!result.ok) {
      setSnapshot((previous) => previous.state === "ready" || previous.state === "stale"
        ? previous.data.account_id === accountId
          ? { state: "stale", data: previous.data, error: result.error }
          : { state: "unavailable", error: result.error }
        : { state: "unavailable", error: result.error });
      return;
    }
    setSnapshot(snapshotIsStale(result.data, currentTime)
      ? { state: "stale", data: result.data }
      : { state: "ready", data: result.data });
  }, [accountId, client, clock]);

  useEffect(() => {
    void refresh();
    return () => { latestRead.current += 1; };
  }, [refresh]);

  useEffect(() => {
    if (snapshot.state !== "ready" || snapshot.data.account_id !== accountId) return;
    const observedAtMs = Date.parse(snapshot.data.broker_observed_at);
    const untilStale = observedAtMs + PAPER_ACCOUNT_STALE_AFTER_MS - nowMs + 1;
    if (untilStale <= 0) {
      setSnapshot({ state: "stale", data: snapshot.data });
      return;
    }
    const timer = window.setTimeout(() => {
      const currentTime = clock();
      setNowMs(currentTime);
      if (snapshotIsStale(snapshot.data, currentTime)) {
        setSnapshot({ state: "stale", data: snapshot.data });
      }
    }, Math.min(untilStale, 2_147_000_000));
    return () => window.clearTimeout(timer);
  }, [accountId, clock, nowMs, snapshot]);

  // A prop change renders before its effect starts the next read. Never show a
  // snapshot under a different account label during that render gap.
  const snapshotForAccount: SnapshotState = snapshot.state === "ready" || snapshot.state === "stale"
    ? snapshot.data.account_id === accountId ? snapshot : { state: "loading" }
    : snapshot;
  const data = snapshotForAccount.state === "ready" || snapshotForAccount.state === "stale"
    ? snapshotForAccount.data
    : null;

  return <main aria-labelledby="paper-account-title">
    <h1 id="paper-account-title">Paper account positions</h1>
    <p>Read-only broker snapshot for account {accountId}. LIVE trading is disabled.</p>
    <button type="button" aria-label="LIVE disabled" disabled>LIVE disabled</button>
    {statusBanner(snapshotForAccount)}
    {snapshotForAccount.state === "loading" && <button type="button" disabled>Refresh snapshot</button>}
    {snapshotForAccount.state !== "loading" && <button type="button" onClick={() => void refresh()} disabled={refreshing}>
      {refreshing ? "Refreshing…" : "Refresh snapshot"}
    </button>}
    {data && <>
      <section aria-label="Account equity and balances">
        <h2>Equity and balances</h2>
        {data.equity
          ? <p>Equity ({data.equity.kind}): {data.equity.currency} {data.equity.amount}</p>
          : <p>Equity unavailable — no declared equity evidence was provided.</p>}
        {data.balances === null
          ? <p>Balances unavailable in this snapshot.</p>
          : data.balances.length === 0
            ? <p>No balances in this snapshot.</p>
            : <ul aria-label="Account balances">
              {data.balances.map((balance) => <li key={balance.currency}>
                {balance.currency}: {balance.amount}
              </li>)}
            </ul>}
      </section>
      <section aria-label="Broker-reported positions">
        <h2>Broker positions (paper snapshot)</h2>
        {data.positions.length === 0
          ? <p>No positions in the broker snapshot.</p>
          : <ul>
            {data.positions.map((position) => <li key={position.instrument_id}>
              {position.instrument_id}: {position.quantity}
            </li>)}
          </ul>}
      </section>
      <section aria-label="Snapshot source">
        <h2>Snapshot source</h2>
        <p>Broker revision: {data.broker_revision}</p>
        <p>Environment: PAPER</p>
        <p>Broker observation time: <time dateTime={data.broker_observed_at}>{data.broker_observed_at}</time></p>
      </section>
    </>}
  </main>;
}
