import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  createMassCancelIdempotencyKey,
  createPaperMassCancelApi,
  isSafeMassCancelIdentifier,
  isValidPaperMassCancelPlan,
} from "./api";
import type {
  PaperMassCancelApiResult,
  PaperMassCancelOrderRequestV1,
  PaperMassCancelOrderResultV1,
  PaperMassCancelPlanV1,
  PaperMassCancelRequestV1,
} from "./api";

export interface PaperMassCancelViewProps {
  plan: PaperMassCancelPlanV1;
  fetcher?: typeof fetch;
  refreshBrokerRevision?: () => Promise<number>;
  idempotencyKeyFactory?: () => string;
}

type Operation = {
  identity: string;
  request: Omit<PaperMassCancelRequestV1, "expected_broker_revision" | "start_index">;
};

type Progress =
  | { state: "ready"; completed: 0; results: [] }
  | { state: "partial"; completed: number; cursor: number; results: PaperMassCancelOrderResultV1[]; message?: string }
  | { state: "complete"; completed: number; results: PaperMassCancelOrderResultV1[] }
  | { state: "unknown"; completed: number; results: PaperMassCancelOrderResultV1[]; message: string }
  | { state: "rejected"; completed: number; results: PaperMassCancelOrderResultV1[]; message: string };

const ERROR_MESSAGES: Record<string, string> = {
  OUTCOME_UNKNOWN: "Outcome UNKNOWN. The request may have reached the cancellation service; no cancellation success is inferred.",
  OPERATOR_REQUIRED: "An authorized local operator session is required.",
  PAPER_SCOPE_REQUIRED: "The server could not verify a paper account scope.",
  PAPER_SCOPE_MISMATCH: "The paper account or venue did not match the server's current scope.",
  PRINCIPAL_VENUE_MISMATCH: "The operator session is not authorized for this venue.",
  STALE_OR_MISMATCHED_ACCOUNT_VIEW: "The account view is stale or changed. Refresh the paper account before continuing.",
  ORDER_MISSING_OR_STALE: "At least one remaining order is no longer open in the current paper account view.",
  AMBIGUOUS_NATIVE_ORDER_MAPPING: "The server could not verify a unique venue order mapping.",
  DUPLICATE_ORDER_ID: "The request contains a duplicate venue order identifier.",
  DUPLICATE_MASS_CANCEL_ORDER: "The request contains a duplicate order.",
  INVALID_MASS_CANCEL_CURSOR: "The continuation cursor is invalid; no further request was sent.",
  INVALID_MASS_CANCEL_SCOPE: "The cancellation scope is invalid.",
  MASS_CANCEL_SCOPE_MISMATCH: "The orders do not match the selected cancellation scope.",
  INVALID_MASS_CANCEL_REQUEST: "The cancellation request is invalid.",
  MASS_CANCEL_BATCH_LIMIT: "The cancellation batch exceeds the supported limit.",
  MASS_CANCEL_BODY_TOO_LARGE: "The cancellation request exceeds the supported size.",
  BROKER_OUTCOME_UNKNOWN: "Outcome UNKNOWN. Broker state could not be verified; no cancellation success is inferred.",
  HALT_STATE_UNKNOWN: "Cancellation is blocked because HALT state could not be verified.",
  MASS_CANCEL_OUTCOME_UNKNOWN: "Outcome UNKNOWN. The cancellation service could not confirm the result.",
  MASS_CANCEL_RESULT_INVALID: "Outcome UNKNOWN. The cancellation service returned an unverifiable result.",
  REQUEST_REJECTED: "The cancellation request was rejected or unavailable.",
  PLAN_INVALID: "The paper cancellation plan is incomplete or invalid; no request was sent.",
  KEY_UNAVAILABLE: "A unique request key could not be prepared; no request was sent.",
  REVISION_UNAVAILABLE: "A fresh broker revision could not be read; no resume request was sent.",
  PLAN_CHANGED: "The selected plan changed while cancellation was pending. Outcome UNKNOWN; completion is not inferred and further requests are stopped.",
};

function planIdentity(plan: PaperMassCancelPlanV1): string {
  return JSON.stringify([
    plan.environment,
    plan.account_id,
    plan.venue,
    plan.scope,
    plan.requests.map((item) => [
      item.order_id,
      item.client_order_id,
      item.venue_order_id,
      item.instrument_id,
      item.strategy_id,
      item.side,
      item.protective_leg,
      item.gtd_expiry_ns,
    ]),
  ]);
}

function makeOperation(
  plan: PaperMassCancelPlanV1,
  keyFactory: () => string,
): Operation | null {
  try {
    const rootKey = keyFactory();
    if (!isSafeMassCancelIdentifier(rootKey)) return null;
    const seenKeys = new Set([rootKey]);
    const requests: PaperMassCancelOrderRequestV1[] = plan.requests.map((item) => {
      const key = keyFactory();
      if (!isSafeMassCancelIdentifier(key) || seenKeys.has(key)) {
        throw new Error("INVALID_IDEMPOTENCY_KEY");
      }
      seenKeys.add(key);
      return { ...item, idempotency_key: key };
    });
    return {
      identity: planIdentity(plan),
      request: {
        account_id: plan.account_id,
        venue: plan.venue,
        scope: plan.scope,
        idempotency_key: rootKey,
        requests,
      },
    };
  } catch {
    return null;
  }
}

function cumulativeResultsMatch(
  results: readonly PaperMassCancelOrderResultV1[],
  requests: readonly PaperMassCancelOrderRequestV1[],
  count: number,
): boolean {
  if (results.length !== count || count > requests.length) return false;
  const ids = new Set<string>();
  for (let index = 0; index < count; index += 1) {
    const result = results[index];
    const request = requests[index];
    if (
      result === undefined ||
      request === undefined ||
      result.order_id !== request.order_id ||
      result.idempotency_key !== request.idempotency_key ||
      ids.has(result.order_id)
    ) return false;
    ids.add(result.order_id);
  }
  return true;
}

function orderResultLabel(result: PaperMassCancelOrderResultV1): string {
  return "Order " + result.order_id;
}

function codeList(values: readonly string[]): string {
  return values.length === 0 ? "None" : values.join(", ");
}

function ResultList({ results }: { results: readonly PaperMassCancelOrderResultV1[] }) {
  if (results.length === 0) return <p>No per-order results have been received.</p>;
  return (
    <ol aria-label="Paper mass cancellation results">
      {results.map((result) => (
        <li key={result.order_id + ":" + result.idempotency_key}>
          <article aria-label={orderResultLabel(result)}>
            <h3>{orderResultLabel(result)}</h3>
            <p>Lifecycle status: {result.lifecycle_state}</p>
            <p>OMS status: {result.oms_state ?? "Not reported"}</p>
            <p>Reason code: {result.reason_code}</p>
            <p>Child dispatch stopped: {result.child_dispatch_stopped ? "Yes" : "No"}</p>
            <p>Cancel sent: {result.cancel_sent ? "Yes" : "No"}</p>
            <p>Reconciled: {result.reconciled ? "Yes" : "No"}</p>
            <p>Discrepancy codes: {codeList(result.discrepancy_codes)}</p>
            <p>Operator alert codes: {codeList(result.operator_alert_codes)}</p>
            <p>Fill execution IDs: {codeList(result.fill_execution_ids)}</p>
          </article>
        </li>
      ))}
    </ol>
  );
}

function messageFor(code: string): string {
  return ERROR_MESSAGES[code] ?? ERROR_MESSAGES.REQUEST_REJECTED ?? "The request was rejected or unavailable.";
}

export function PaperMassCancelView({
  plan,
  fetcher = fetch,
  refreshBrokerRevision,
  idempotencyKeyFactory = createMassCancelIdempotencyKey,
}: PaperMassCancelViewProps) {
  const api = useMemo(() => createPaperMassCancelApi(fetcher), [fetcher]);
  const operationRef = useRef<Operation | null>(null);
  const inFlightRef = useRef(false);
  const mountedRef = useRef(false);
  const currentPlanIdentityRef = useRef<string | null>(null);
  const previousPlanIdentityRef = useRef<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<Progress>({
    state: "ready",
    completed: 0,
    results: [],
  });

  const planValid = isValidPaperMassCancelPlan(plan);
  const live = plan.environment === "live";
  const total = planValid ? plan.requests.length : 0;
  const currentPlanIdentity = planValid ? planIdentity(plan) : null;
  currentPlanIdentityRef.current = currentPlanIdentity;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useLayoutEffect(() => {
    const previousIdentity = previousPlanIdentityRef.current;
    previousPlanIdentityRef.current = currentPlanIdentity;
    if (previousIdentity === null || previousIdentity === currentPlanIdentity) return;

    const unresolved = progress.state === "partial" || progress.state === "unknown";
    operationRef.current = null;
    if (unresolved) {
      setProgress({
        state: "unknown",
        completed: 0,
        results: [],
        message: messageFor("PLAN_CHANGED"),
      });
    } else {
      setProgress({ state: "ready", completed: 0, results: [] });
    }
  }, [currentPlanIdentity, progress.state]);

  const applyResult = (
    result: PaperMassCancelApiResult<{
      request_idempotency_key: string;
      start_index: number;
      next_index: number | null;
      complete: boolean;
      results: PaperMassCancelOrderResultV1[];
    }>,
    operation: Operation,
    startIndex: number,
    priorResults: readonly PaperMassCancelOrderResultV1[],
  ) => {
    if (!mountedRef.current) return;
    if (operation.identity !== currentPlanIdentityRef.current) {
      setProgress({
        state: "unknown",
        completed: 0,
        results: [],
        message: messageFor("PLAN_CHANGED"),
      });
      return;
    }
    if (!result.ok) {
      if (result.error === "OUTCOME_UNKNOWN" ||
        result.error === "BROKER_OUTCOME_UNKNOWN" ||
        result.error === "MASS_CANCEL_OUTCOME_UNKNOWN" ||
        result.error === "MASS_CANCEL_RESULT_INVALID") {
        setProgress({
          state: "unknown",
          completed: priorResults.length,
          results: [...priorResults],
          message: messageFor(result.error),
        });
        return;
      }
      if (startIndex > 0) {
        setProgress({
          state: "partial",
          completed: priorResults.length,
          cursor: startIndex,
          results: [...priorResults],
          message: messageFor(result.error),
        });
        return;
      }
      setProgress({
        state: "rejected",
        completed: 0,
        results: [],
        message: messageFor(result.error),
      });
      return;
    }

    const page = result.data;
    const combined = [...priorResults, ...page.results];
    const nextIndex = page.next_index;
    if (
      page.start_index !== startIndex ||
      page.request_idempotency_key !== operation.request.idempotency_key ||
      (nextIndex === null && !page.complete) ||
      (nextIndex !== null && page.complete) ||
      (nextIndex !== null && (
        !Number.isSafeInteger(nextIndex) ||
        nextIndex <= startIndex ||
        nextIndex > operation.request.requests.length ||
        page.results.length !== nextIndex - startIndex
      ))
    ) {
      setProgress({
        state: "unknown",
        completed: priorResults.length,
        results: [...priorResults],
        message: messageFor("MASS_CANCEL_RESULT_INVALID"),
      });
      return;
    }

    if (page.complete) {
      const allCovered = nextIndex === null &&
        page.results.length === operation.request.requests.length - startIndex &&
        cumulativeResultsMatch(
          combined,
          operation.request.requests,
          operation.request.requests.length,
        );
      if (!allCovered) {
        setProgress({
          state: "unknown",
          completed: priorResults.length,
          results: [...priorResults],
          message: messageFor("MASS_CANCEL_RESULT_INVALID"),
        });
        return;
      }
      setProgress({
        state: "complete",
        completed: operation.request.requests.length,
        results: combined,
      });
      return;
    }

    const cursor = nextIndex;
    if (
      cursor === null ||
      !cumulativeResultsMatch(combined, operation.request.requests, cursor)
    ) {
      setProgress({
        state: "unknown",
        completed: priorResults.length,
        results: [...priorResults],
        message: messageFor("MASS_CANCEL_RESULT_INVALID"),
      });
      return;
    }
    setProgress({
      state: "partial",
      completed: cursor,
      cursor,
      results: combined,
    });
  };

  const submitPage = async (
    operation: Operation,
    expectedRevision: number,
    startIndex: number,
    priorResults: readonly PaperMassCancelOrderResultV1[],
  ) => {
    const request: PaperMassCancelRequestV1 = {
      ...operation.request,
      expected_broker_revision: expectedRevision,
      start_index: startIndex,
    };
    const response = await api.submit(request);
    applyResult(response, operation, startIndex, priorResults);
  };

  const confirm = async () => {
    if (
      inFlightRef.current ||
      live ||
      !planValid ||
      progress.state !== "ready"
    ) return;
    inFlightRef.current = true;
    setBusy(true);
    try {
      const operation = makeOperation(plan, idempotencyKeyFactory);
      if (operation === null) {
        setProgress({
          state: "rejected",
          completed: 0,
          results: [],
          message: messageFor("KEY_UNAVAILABLE"),
        });
        return;
      }
      operationRef.current = operation;
      await submitPage(
        operation,
        plan.expected_broker_revision,
        0,
        [],
      );
    } finally {
      inFlightRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  };

  const resume = async () => {
    if (
      inFlightRef.current ||
      live ||
      progress.state !== "partial" ||
      progress.cursor >= total ||
      refreshBrokerRevision === undefined
    ) return;
    const operation = operationRef.current;
    if (operation === null || operation.identity !== planIdentity(plan)) {
      operationRef.current = null;
      setProgress({
        state: "unknown",
        completed: 0,
        results: [],
        message: messageFor("PLAN_CHANGED"),
      });
      return;
    }

    inFlightRef.current = true;
    setBusy(true);
    try {
      let revision: number;
      try {
        revision = await refreshBrokerRevision();
      } catch {
        revision = Number.NaN;
      }
      if (!mountedRef.current) return;
      if (operation.identity !== currentPlanIdentityRef.current) {
        setProgress({
          state: "unknown",
          completed: 0,
          results: [],
          message: messageFor("PLAN_CHANGED"),
        });
        return;
      }
      if (!Number.isSafeInteger(revision) || revision < 0) {
        setProgress({
          state: "partial",
          completed: progress.completed,
          cursor: progress.cursor,
          results: progress.results,
          message: messageFor("REVISION_UNAVAILABLE"),
        });
        return;
      }
      await submitPage(
        operation,
        revision,
        progress.cursor,
        progress.results,
      );
    } finally {
      inFlightRef.current = false;
      if (mountedRef.current) setBusy(false);
    }
  };

  const completed = progress.completed;
  const remaining = Math.max(0, total - completed);
  const actionDisabled = busy || live || !planValid;
  const canResume = progress.state === "partial" &&
    progress.cursor < total &&
    refreshBrokerRevision !== undefined;

  return (
    <main className="tab-content" aria-labelledby="paper-mass-cancel-title">
      <section className="panel panel--full" aria-label="Paper mass cancellation">
        <h1 id="paper-mass-cancel-title" className="panel__heading">Paper mass cancel</h1>
        <p>Environment: {live ? "LIVE" : "PAPER"}</p>
        <p>Account: {isSafeMassCancelIdentifier(plan.account_id) ? plan.account_id : "Unavailable"}</p>
        <p>Venue: {isSafeMassCancelIdentifier(plan.venue) ? plan.venue : "Unavailable"}</p>
        <p>Scope: {planValid ? plan.scope : "Unavailable"}</p>
        <p>Orders in the confirmed request: {total}</p>
        {live && <p role="alert">LIVE cancellation is unavailable. No request was sent.</p>}
        {!planValid && <p role="alert">The accepted paper cancellation plan is missing or invalid. No request was sent.</p>}
        {planValid && !live && progress.state === "ready" && (
          <button type="button" disabled={actionDisabled} onClick={() => void confirm()}>
            Confirm mass cancel of {total} orders
          </button>
        )}
        {progress.state === "partial" && (
          <>
            <p role="status">Cancellation has not been marked complete by the API.</p>
            {!canResume && progress.cursor < total && (
              <p role="status">A fresh broker revision is required before resuming.</p>
            )}
            {progress.cursor >= total && (
              <p role="status">All requested orders have results, but the API has not marked the operation complete. No success is inferred.</p>
            )}
            <button type="button" disabled={busy || live || !canResume} onClick={() => void resume()}>
              {busy ? "Refreshing account and resuming…" : "Resume with returned cursor"}
            </button>
          </>
        )}
        {progress.state === "complete" && <p role="status">Complete: every requested order has exactly one API result.</p>}
        {progress.state === "unknown" && <p role="alert">{progress.message}</p>}
        {progress.state === "rejected" && <p role="alert">{progress.message}</p>}
        {progress.state === "partial" && progress.message && <p role="alert">{progress.message}</p>}
        {(progress.state === "partial" || progress.state === "complete" || progress.state === "unknown") && total > 0 && (
          <section aria-label="Cancellation progress">
            <p>Completed: {completed}</p>
            <p>Remaining: {remaining}</p>
            <progress aria-label="Cancellation progress" max={total} value={completed} />
          </section>
        )}
        <ResultList results={progress.results} />
      </section>
    </main>
  );
}
