import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import {
  getKnowledgeIngestion,
  KnowledgeArchiveError,
  isSafeKnowledgeArchiveTag,
  listKnowledgeIngestionRuns,
  listKnowledgeIngestions,
} from "../api/knowledgeArchive";
import type {
  KnowledgeArchiveDetailV1,
  KnowledgeArchiveEntryV1,
  KnowledgeArchiveErrorCodeV1,
  KnowledgeArchivePageV1,
  KnowledgeArchiveQueryV1,
  KnowledgeArchiveSourceTypeV1,
} from "../api/knowledgeArchive";
import {
  errorPanel,
  evaluatePanelState,
  freshPanel,
  loadingPanel,
  OPERATOR_STALE_MS,
  unavailablePanel,
} from "../../state/panelState";
import type { Clock, PanelState } from "../../state/panelState";

const SOURCE = "Knowledge Archive API";
const SOURCE_TIME_UNAVAILABLE = "Source timestamp unavailable; metadata is API-reported only.";
const SOURCE_TYPES: readonly KnowledgeArchiveSourceTypeV1[] = ["web", "file", "api", "custom"];

type ViewData<T> = {
  value: T | null;
  panel: PanelState<T>;
  receivedAt: number | null;
};

type FetchLike = typeof fetch;

function initialViewData<T>(): ViewData<T> {
  return { value: null, panel: loadingPanel<T>(), receivedAt: null };
}

function sourceTimestamp(value: number | string | undefined): number | string | undefined {
  return value;
}

function panelForSuccess<T>(value: T, sourceAsOf: number | string | undefined, now: number): PanelState<T> {
  if (sourceAsOf === undefined) return unavailablePanel(SOURCE, SOURCE_TIME_UNAVAILABLE);
  const candidate = freshPanel(value, SOURCE, sourceTimestamp(sourceAsOf), () => now);
  return candidate.status === "fresh"
    ? evaluatePanelState(candidate, () => now, OPERATOR_STALE_MS)
    : candidate;
}

function panelForError<T>(error: unknown, retry: () => void): PanelState<T> {
  if (error instanceof KnowledgeArchiveError && error.code === "OPERATOR_SESSION_UNAVAILABLE") {
    return unavailablePanel(SOURCE, "operator session unavailable");
  }
  const code: KnowledgeArchiveErrorCodeV1 = error instanceof KnowledgeArchiveError
    ? error.code
    : "NETWORK_UNAVAILABLE";
  return errorPanel(SOURCE, code, undefined, retry);
}

function receivedLabel(receivedAt: number | null): string {
  return receivedAt === null ? "No response received in this session." : `Response received at ${new Date(receivedAt).toLocaleString()}.`;
}

function StateNotice<T>({ panel, receivedAt }: { panel: PanelState<T>; receivedAt: number | null }) {
  if (panel.status === "fresh") return <p role="status">Source timestamp verified. {receivedLabel(receivedAt)}</p>;
  if (panel.status === "stale") {
    return <p role="status">Source timestamp is stale. Last source update: {new Date(panel.asOf).toLocaleString()}. {receivedLabel(receivedAt)}</p>;
  }
  if (panel.status === "loading") return <p role="status">Loading archive metadata…</p>;
  if (panel.status === "unavailable") return <p role="status">{panel.reason} {receivedLabel(receivedAt)}</p>;
  return (
    <div role="alert">
      <p>Archive request failed: {panel.code}.</p>
      <p>{receivedLabel(receivedAt)}</p>
      {panel.retry && <button type="button" onClick={panel.retry}>Retry</button>}
    </div>
  );
}

function Metadata({ entry }: { entry: KnowledgeArchiveEntryV1 }) {
  return (
    <dl>
      <dt>Ingestion ID</dt><dd>{entry.id}</dd>
      <dt>Source type</dt><dd>{entry.sourceType}</dd>
      <dt>Status</dt><dd>{entry.status}</dd>
      <dt>Created (ns)</dt><dd>{entry.createdAtNs}</dd>
      <dt>Updated (ns)</dt><dd>{entry.updatedAtNs}</dd>
      <dt>Tags</dt><dd>{entry.tags.length ? entry.tags.join(", ") : "None"}</dd>
    </dl>
  );
}

export function KnowledgeArchiveView({
  fetcher = fetch,
  clock = Date.now,
}: {
  fetcher?: FetchLike;
  clock?: Clock;
}) {
  const [sourceType, setSourceType] = useState<KnowledgeArchiveSourceTypeV1 | "">("");
  const [tag, setTag] = useState("");
  const [createdAfter, setCreatedAfter] = useState("");
  const [createdBefore, setCreatedBefore] = useState("");
  const [tagFilterInvalid, setTagFilterInvalid] = useState(false);
  const [listData, setListData] = useState<ViewData<KnowledgeArchivePageV1>>(initialViewData);
  const [detailData, setDetailData] = useState<ViewData<KnowledgeArchiveDetailV1>>(initialViewData);
  const [runsData, setRunsData] = useState<ViewData<KnowledgeArchivePageV1>>(initialViewData);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [now, setNow] = useState(clock);
  const listGeneration = useRef(0);
  const detailGeneration = useRef(0);
  const runsGeneration = useRef(0);
  const selectedIdRef = useRef<string | null>(null);

  const loadList = useCallback(async (nextQuery: KnowledgeArchiveQueryV1) => {
    const generation = ++listGeneration.current;
    setListData({ value: null, panel: loadingPanel<KnowledgeArchivePageV1>(), receivedAt: null });
    try {
      const value = await listKnowledgeIngestions(nextQuery, fetcher);
      if (generation !== listGeneration.current) return;
      const receivedAt = clock();
      setNow(receivedAt);
      setListData({ value, panel: panelForSuccess(value, value.sourceAsOf, receivedAt), receivedAt });
    } catch (error) {
      if (generation !== listGeneration.current) return;
      setListData({ value: null, panel: panelForError(error, () => { void loadList(nextQuery); }), receivedAt: null });
    }
  }, [clock, fetcher]);

  const loadDetail = useCallback(async (id: string) => {
    if (selectedIdRef.current !== id) return;
    const generation = ++detailGeneration.current;
    setDetailData({ value: null, panel: loadingPanel<KnowledgeArchiveDetailV1>(), receivedAt: null });
    try {
      const value = await getKnowledgeIngestion(id, fetcher);
      if (generation !== detailGeneration.current || selectedIdRef.current !== id) return;
      const receivedAt = clock();
      setNow(receivedAt);
      setDetailData({ value, panel: panelForSuccess(value, value.sourceAsOf, receivedAt), receivedAt });
    } catch (error) {
      if (generation !== detailGeneration.current || selectedIdRef.current !== id) return;
      setDetailData({ value: null, panel: panelForError(error, () => { void loadDetail(id); }), receivedAt: null });
    }
  }, [clock, fetcher]);

  const loadRuns = useCallback(async (id: string) => {
    if (selectedIdRef.current !== id) return;
    const generation = ++runsGeneration.current;
    setRunsData({ value: null, panel: loadingPanel<KnowledgeArchivePageV1>(), receivedAt: null });
    try {
      const value = await listKnowledgeIngestionRuns(id, { limit: 50 }, fetcher);
      if (generation !== runsGeneration.current || selectedIdRef.current !== id) return;
      const receivedAt = clock();
      setNow(receivedAt);
      setRunsData({ value, panel: panelForSuccess(value, value.sourceAsOf, receivedAt), receivedAt });
    } catch (error) {
      if (generation !== runsGeneration.current || selectedIdRef.current !== id) return;
      setRunsData({ value: null, panel: panelForError(error, () => { void loadRuns(id); }), receivedAt: null });
    }
  }, [clock, fetcher]);

  const loadSelected = useCallback((id: string) => {
    selectedIdRef.current = id;
    detailGeneration.current += 1;
    runsGeneration.current += 1;
    setSelectedId(id);
    setDetailData({ value: null, panel: loadingPanel<KnowledgeArchiveDetailV1>(), receivedAt: null });
    setRunsData({ value: null, panel: loadingPanel<KnowledgeArchivePageV1>(), receivedAt: null });
    void loadDetail(id);
    void loadRuns(id);
  }, [loadDetail, loadRuns]);

  useEffect(() => {
    void loadList({ limit: 50 });
    return () => {
      listGeneration.current += 1;
      detailGeneration.current += 1;
      runsGeneration.current += 1;
      selectedIdRef.current = null;
    };
  }, [loadList]);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(clock()), 1_000);
    return () => window.clearInterval(timer);
  }, [clock]);

  const currentListPanel = listData.panel.status === "fresh"
    ? evaluatePanelState(listData.panel, () => now, OPERATOR_STALE_MS)
    : listData.panel;
  const currentDetailPanel = detailData.panel.status === "fresh"
    ? evaluatePanelState(detailData.panel, () => now, OPERATOR_STALE_MS)
    : detailData.panel;
  const currentRunsPanel = runsData.panel.status === "fresh"
    ? evaluatePanelState(runsData.panel, () => now, OPERATOR_STALE_MS)
    : runsData.panel;

  function submitFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (tag !== "" && !isSafeKnowledgeArchiveTag(tag)) {
      setTagFilterInvalid(true);
      ++listGeneration.current;
      ++detailGeneration.current;
      ++runsGeneration.current;
      selectedIdRef.current = null;
      setSelectedId(null);
      setListData(initialViewData());
      setDetailData(initialViewData());
      setRunsData(initialViewData());
      return;
    }
    setTagFilterInvalid(false);
    selectedIdRef.current = null;
    ++detailGeneration.current;
    ++runsGeneration.current;
    setSelectedId(null);
    setDetailData(initialViewData());
    setRunsData(initialViewData());
    void loadList({
      limit: 50,
      ...(sourceType ? { sourceType } : {}),
      ...(tag ? { tag } : {}),
      ...(createdAfter ? { createdAfter } : {}),
      ...(createdBefore ? { createdBefore } : {}),
    });
  }

  return (
    <main className="tab-content" aria-labelledby="knowledge-archive-title">
      <section className="panel panel--full" aria-label="Knowledge Archive">
        <h2 id="knowledge-archive-title" className="panel__heading">Knowledge Archive</h2>
        <p>Read-only archive metadata. Archived content is not displayed.</p>
        <form onSubmit={submitFilters} aria-label="Filter archived ingestions">
          <label htmlFor="knowledge-source-filter">Source type</label>
          <select id="knowledge-source-filter" value={sourceType} onChange={(event) => setSourceType(event.target.value as KnowledgeArchiveSourceTypeV1 | "")}>
            <option value="">All source types</option>
            {SOURCE_TYPES.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <label htmlFor="knowledge-tag-filter">Tag</label>
          <input id="knowledge-tag-filter" value={tag} onChange={(event) => { setTag(event.target.value); setTagFilterInvalid(false); }} maxLength={64} />
          <label htmlFor="knowledge-created-after-filter">Created after (ns)</label>
          <input id="knowledge-created-after-filter" inputMode="numeric" value={createdAfter} onChange={(event) => setCreatedAfter(event.target.value)} />
          <label htmlFor="knowledge-created-before-filter">Created before (ns)</label>
          <input id="knowledge-created-before-filter" inputMode="numeric" value={createdBefore} onChange={(event) => setCreatedBefore(event.target.value)} />
          <button type="submit">Apply filters</button>
        </form>
        {tagFilterInvalid && <p role="alert">Invalid tag filter.</p>}
        <StateNotice panel={currentListPanel} receivedAt={listData.receivedAt} />
        {listData.value && (
          <div aria-label="API-reported archive metadata">
            <p>API-reported metadata; source freshness is unverified unless a source timestamp is supplied.</p>
            {listData.value.items.length === 0
              ? <p>No archived ingestions found.</p>
              : <ul aria-label="Archived ingestions">
                  {listData.value.items.map((entry) => (
                    <li key={entry.id}>
                      <button type="button" aria-label={`View ingestion ${entry.id}`} onClick={() => { void loadSelected(entry.id); }}>
                        {entry.id} — {entry.sourceType} — {entry.status}
                      </button>
                    </li>
                  ))}
                </ul>}
            {listData.value.warnings.length > 0 && <p>Some filter parameters were ignored by the archive service.</p>}
            {listData.value.nextCursor && <button type="button" onClick={() => {
              const nextCursor = listData.value?.nextCursor ?? undefined;
              void loadList({
                limit: 50,
                ...(sourceType ? { sourceType } : {}),
                ...(tag ? { tag } : {}),
                ...(createdAfter ? { createdAfter } : {}),
                ...(createdBefore ? { createdBefore } : {}),
                ...(nextCursor ? { cursor: nextCursor } : {}),
              });
            }}>Next page</button>}
          </div>
        )}
      </section>
      {selectedId && (
        <div className="panel-grid">
          <section className="panel" aria-label="Ingestion detail">
            <h3>Ingestion detail</h3>
            <StateNotice panel={currentDetailPanel} receivedAt={detailData.receivedAt} />
            {detailData.value && <Metadata entry={detailData.value} />}
          </section>
          <section className="panel" aria-label="Ingestion runs">
            <h3>Ingestion runs</h3>
            <StateNotice panel={currentRunsPanel} receivedAt={runsData.receivedAt} />
            {runsData.value && (runsData.value.items.length === 0
              ? <p>No archived runs found.</p>
              : <ul>{runsData.value.items.map((run) => <li key={run.id}><Metadata entry={run} /></li>)}</ul>)}
          </section>
        </div>
      )}
    </main>
  );
}
