import { useEffect, useState } from "react";
import { PanelCard } from "./PanelCard";
import { evaluatePanelState, freshPanel, STREAM_STALE_MS, unavailablePanel } from "../state/panelState";

export function StreamHealthPanel({ fixture, clock = Date.now }: {
  fixture: "healthy" | "stale" | null; clock?: () => number;
}) {
  const [mountedAt] = useState(clock);
  const [now, setNow] = useState(clock());
  useEffect(() => {
    const id = window.setInterval(() => setNow(clock()), 250);
    return () => window.clearInterval(id);
  }, [clock]);
  const state = fixture
    ? evaluatePanelState(freshPanel({ records: 0 }, "Fixture", mountedAt - (fixture === "stale" ? STREAM_STALE_MS + 1_000 : 0), () => mountedAt), () => now, STREAM_STALE_MS)
    : unavailablePanel<{ records: number }>("Gateway stream", "No timestamped terminal stream is connected.");
  return <div className="cc-stream"><div className="cc-section-title"><span>STREAM FRESHNESS</span><span>3 SECOND STALE THRESHOLD</span></div>
    <PanelCard title="Terminal stream" eyebrow="DIAGNOSTIC / SOURCE STATE" state={state} staleLabel="Stale"
      renderData={(data) => <div className="fixture-content"><strong>Packet received</strong><span>{data.records} market records supplied. This is a local fixture.</span></div>} /></div>;
}
