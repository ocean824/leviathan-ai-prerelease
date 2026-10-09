import { useEffect, useMemo, useRef, useState } from "react";
import {
  assessPaperRisk,
  PaperRiskAssessmentError,
  type PaperRiskAssessmentRequest,
} from "../paperRiskReview/api";
import { PaperRiskReviewView } from "../paperRiskReview/PaperRiskReviewView";
import type { PaperOrderTicketApi, PaperOrderErrorCode, PaperOrderCreateRequest, PaperOrderSnapshot } from "./api";
import { createPaperOrderTicketApi, PAPER_ORDER_ENVIRONMENT } from "./api";
import { isSafeIdentifier } from "../../shared/safeLabel";

export interface PaperOrderTicketScope {
  readonly environment: "paper";
  readonly account_id: string;
  readonly venue: string;
  readonly instrument_id: string;
  readonly strategy_id: string;
  readonly active: true;
}

export interface PaperOrderTicketInstrument {
  readonly native_contract_id: string;
  readonly contract_multiplier: string;
  readonly currency: string;
}

export interface PaperOrderTicketPriceEvidence {
  readonly price: string;
  readonly price_source_ns: number;
  readonly price_ingest_ns: number;
  readonly price_source_id: string;
}

export interface PaperOrderTicketViewProps {
  /** Must be supplied from the host's trusted local-operator session. */
  readonly trustedOperator: boolean;
  /** Scope-specific host evidence; aggregate order status is not sufficient. */
  readonly activePaperScope: PaperOrderTicketScope | null;
  /** Instrument and price evidence are selected by the host, never by environment/provider UI. */
  readonly instrument: PaperOrderTicketInstrument;
  readonly priceEvidence: PaperOrderTicketPriceEvidence;
  readonly client?: PaperOrderTicketApi;
}

interface FormState {
  readonly side: "BUY" | "SELL";
  readonly quantity: string;
  readonly orderType: "MARKET" | "LIMIT";
  readonly timeInForce: "DAY" | "GTC" | "GTD";
  readonly limitPrice: string;
  readonly expiresAt: string;
}

interface PreparedIntent {
  readonly request: PaperRiskAssessmentRequest;
  readonly requestIdentity: string;
  readonly ticketIdentity: string;
  readonly idempotencyKey: string;
  readonly policyDigest: string;
}

const INITIAL_FORM: FormState = {
  side: "BUY", quantity: "", orderType: "MARKET", timeInForce: "DAY", limitPrice: "", expiresAt: "",
};
const MAX_EVIDENCE_RETRIES = 2;

const ORDER_ERROR_TEXT: Record<PaperOrderErrorCode, { readonly field: string; readonly text: string }> = {
  NETWORK_UNAVAILABLE: { field: "order", text: "The order service could not be reached. Check order status before trying again." },
  OPERATOR_REQUIRED: { field: "scope", text: "A trusted operator session is required. Sign in again before submitting." },
  ACTIVATION_DENIED: { field: "scope", text: "Paper dispatch is not authorized for this scope. Verify the active paper scope." },
  ACTIVATION_DISABLED: { field: "scope", text: "Paper dispatch is inactive or recovery is not ready. Reconfirm the paper scope." },
  LIVE_DISABLED: { field: "scope", text: "Only the paper environment can be submitted from this ticket." },
  CREDENTIAL_BINDING_DENIED: { field: "scope", text: "The paper account binding is unavailable. Verify the selected paper account." },
  NATIVE_CONTRACT_DENIED: { field: "instrument", text: "This instrument is not approved for the selected paper venue." },
  HALT_ACTIVE: { field: "risk", text: "A risk halt is active. Clear it through the authorized recovery workflow before dispatch." },
  PAPER_EVIDENCE_DENIED: { field: "risk", text: "Current paper account or risk evidence does not allow dispatch. Refresh the assessment." },
  EVIDENCE_UNAVAILABLE: { field: "risk", text: "Paper evidence is temporarily unavailable. Refresh the risk review before retrying this draft." },
  IDEMPOTENCY_CONFLICT: { field: "order", text: "This order key conflicts with a recorded request. Review order status before retrying." },
  STALE_BROKER_VIEW: { field: "order", text: "The paper venue state changed. Refresh the order and risk evidence before retrying." },
  INVALID_ENVIRONMENT: { field: "scope", text: "The order environment must be paper." },
  INVALID_ORDER_SCOPE: { field: "scope", text: "The paper account, venue, instrument, or strategy scope is invalid." },
  INVALID_ORDER_REQUEST: { field: "order", text: "Review the order fields and correct the invalid request." },
  INVALID_QUANTITY: { field: "quantity", text: "Enter a positive quantity within the supported precision and range." },
  INVALID_LIMIT_PRICE: { field: "limit_price", text: "Enter a positive limit price for a limit order." },
  INVALID_EXPIRY: { field: "expires_at", text: "Enter a valid expiry for a GTD order." },
  INVALID_POLICY_DIGEST: { field: "risk", text: "The risk policy changed. Refresh the assessment before submitting." },
  INVALID_ORDER_IDENTITY: { field: "scope", text: "The paper order identity is invalid. Verify the selected scope." },
  INVALID_ATTEMPT: { field: "order", text: "The order attempt is invalid. Review the order before retrying." },
  POLICY_OUT_OF_BOUNDS: { field: "order", text: "The order exceeds supported policy bounds. Review the order fields." },
  PRECISION_EXCEEDED: { field: "quantity", text: "The order exceeds supported numeric precision." },
  UNSUPPORTED_ORDER: { field: "order_type", text: "Choose a supported market or limit order." },
  UNSUPPORTED_TIF: { field: "time_in_force", text: "Choose DAY, GTC, or GTD time in force." },
  ORDER_NOT_FOUND: { field: "order", text: "The order response could not be matched. Check order status before retrying." },
  HTTP_ERROR: { field: "order", text: "The order service returned an unavailable response. Check order status before retrying." },
  INVALID_RESPONSE: { field: "order", text: "The order service response could not be verified. Check order status before retrying." },
};

const RISK_ERROR_TEXT: Record<string, string> = {
  NETWORK_UNAVAILABLE: "The risk assessment service could not be reached. Submission is blocked.",
  PRINCIPAL_REQUIRED: "A trusted operator session is required. Submission is blocked.",
  PAPER_SCOPE_REQUIRED: "The selected paper scope could not be verified. Submission is blocked.",
  INVALID_REQUEST: "The risk assessment request is invalid. Submission is blocked.",
  ASSESSMENT_UNAVAILABLE: "The risk assessment is unavailable. Submission is blocked.",
  HTTP_ERROR: "The risk assessment request failed. Submission is blocked.",
  INVALID_RESPONSE: "The assessment response could not be verified. Submission is blocked.",
};

function riskIdentity(request: PaperRiskAssessmentRequest): string {
  return JSON.stringify([
    request.scope, request.account_id, request.request_id, request.attempt_id, request.strategy_id,
    request.venue_id, request.instrument_id, request.side, request.quantity, request.price,
    request.contract_multiplier, request.currency, request.price_source_ns, request.price_ingest_ns,
    request.price_source_id,
  ]);
}

function ticketIdentity(props: PaperOrderTicketViewProps, form: FormState): string {
  const scope = props.activePaperScope;
  return JSON.stringify([
    props.trustedOperator, scope?.active, scope?.environment, scope?.account_id, scope?.venue,
    scope?.instrument_id, scope?.strategy_id, props.instrument.native_contract_id,
    props.instrument.contract_multiplier, props.instrument.currency, props.priceEvidence.price,
    props.priceEvidence.price_source_ns, props.priceEvidence.price_ingest_ns,
    props.priceEvidence.price_source_id, form.side, form.quantity, form.orderType,
    form.timeInForce, form.limitPrice, form.expiresAt,
  ]);
}

function validPositiveDecimal(value: string): boolean {
  return /^(?:0|[0-9]+)(?:\.[0-9]+)?$/.test(value) && /[1-9]/.test(value);
}

function isExactActiveScope(scope: PaperOrderTicketScope | null, props: PaperOrderTicketViewProps): boolean {
  return scope !== null && scope.active === true && scope.environment === PAPER_ORDER_ENVIRONMENT &&
    typeof scope.account_id === "string" && scope.account_id.length > 0 &&
    typeof scope.venue === "string" && scope.venue.length > 0 &&
    typeof scope.instrument_id === "string" && scope.instrument_id.length > 0 &&
    typeof scope.strategy_id === "string" && scope.strategy_id.length > 0 &&
    // The instrument is pinned by the parent selection. Editable order controls cannot alter scope.
    props.instrument.native_contract_id.length > 0;
}

function scopeMatchesTicket(scope: PaperOrderTicketScope | null, props: PaperOrderTicketViewProps): boolean {
  return isExactActiveScope(scope, props) && scope !== null &&
    [scope.account_id, scope.venue, scope.instrument_id, scope.strategy_id,
      props.instrument.native_contract_id, props.priceEvidence.price_source_id].every(isSafeIdentifier) &&
    validPositiveDecimal(props.instrument.contract_multiplier) &&
    /^[A-Z]{3}$/.test(props.instrument.currency) &&
    validPositiveDecimal(props.priceEvidence.price) &&
    Number.isInteger(props.priceEvidence.price_source_ns) && Number.isInteger(props.priceEvidence.price_ingest_ns);
}

function fixedRiskError(error: unknown): string {
  const code = error instanceof PaperRiskAssessmentError ? error.code : "ASSESSMENT_UNAVAILABLE";
  return RISK_ERROR_TEXT[code] ?? RISK_ERROR_TEXT.ASSESSMENT_UNAVAILABLE;
}

function orderOutcomeMayBeUnknown(code: PaperOrderErrorCode): boolean {
  return code === "NETWORK_UNAVAILABLE" || code === "HTTP_ERROR" ||
    code === "INVALID_RESPONSE" || code === "IDEMPOTENCY_CONFLICT";
}

function safeOrderIdLabel(orderId: string): string {
  const isUuid4Hex = /^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/i.test(orderId);
  return isSafeIdentifier(orderId) || isUuid4Hex ? orderId : "unverified order identifier";
}

export function PaperOrderTicketView(props: PaperOrderTicketViewProps) {
  const api = useMemo(() => props.client ?? createPaperOrderTicketApi(), [props.client]);
  const [form, setForm] = useState<FormState>(INITIAL_FORM);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [preparing, setPreparing] = useState(false);
  const [prepared, setPrepared] = useState<PreparedIntent | null>(null);
  const [errorText, setErrorText] = useState<string | null>(null);
  const [orderResult, setOrderResult] = useState<PaperOrderSnapshot | null>(null);
  const [dispatchState, setDispatchState] = useState<"idle" | "sending" | "sent" | "unknown" | "retryable" | "retry_exhausted">("idle");
  const inFlightRef = useRef(false);
  const preparingRef = useRef(false);
  const evidenceRetryCountRef = useRef(0);
  const currentRef = useRef({ props, form, prepared, orderResult, dispatchState });
  currentRef.current = { props, form, prepared, orderResult, dispatchState };
  const canShowTicket = props.trustedOperator === true && scopeMatchesTicket(props.activePaperScope, props);
  const scope = props.activePaperScope;
  const hasUnsafeHostIdentifier = [
    scope?.account_id,
    scope?.venue,
    scope?.instrument_id,
    scope?.strategy_id,
    props.instrument.native_contract_id,
    props.priceEvidence.price_source_id,
  ].some((value) => typeof value === "string" && value.length > 0 && !isSafeIdentifier(value));
  const canExplainInvalidPaperEvidence = props.trustedOperator === true &&
    scope?.active === true && scope.environment === PAPER_ORDER_ENVIRONMENT && hasUnsafeHostIdentifier;

  useEffect(() => {
    if (prepared !== null && prepared.ticketIdentity !== ticketIdentity(props, form)) {
      setReviewOpen(false);
      setPrepared(null);
      setErrorText("The order, price evidence, or active paper scope changed. Review the order again.");
    }
  }, [prepared, props, form]);

  if (!canShowTicket) {
    if (!canExplainInvalidPaperEvidence) return null;
    return (
      <section aria-label="Paper order ticket">
        <h2>Paper order ticket</h2>
        <p role="alert">A host-supplied paper identifier could not be verified. Select a supported active paper scope.</p>
      </section>
    );
  }

  const requestFor = (requestId: string): PaperRiskAssessmentRequest => ({
    scope: "paper",
    account_id: props.activePaperScope!.account_id,
    request_id: requestId,
    attempt_id: `${requestId}:1`,
    strategy_id: props.activePaperScope!.strategy_id,
    venue_id: props.activePaperScope!.venue,
    instrument_id: props.activePaperScope!.instrument_id,
    side: form.side,
    quantity: form.quantity,
    price: props.priceEvidence.price,
    contract_multiplier: props.instrument.contract_multiplier,
    currency: props.instrument.currency,
    price_source_ns: props.priceEvidence.price_source_ns,
    price_ingest_ns: props.priceEvidence.price_ingest_ns,
    price_source_id: props.priceEvidence.price_source_id,
  });

  const handleFormChange = (next: FormState) => {
    setForm(next);
    setReviewOpen(false);
    setPrepared(null);
    setErrorText(null);
    setDispatchState("idle");
  };

  async function openReview(): Promise<void> {
    const current = currentRef.current;
    if (
      current.orderResult !== null || current.dispatchState === "unknown" || current.dispatchState === "sending" ||
      preparingRef.current || preparing || inFlightRef.current || !validPositiveDecimal(form.quantity)
    ) return;
    if (form.orderType === "LIMIT" && !validPositiveDecimal(form.limitPrice)) return;
    if (form.timeInForce === "GTD" && !Number.isFinite(Date.parse(form.expiresAt))) return;
    const idempotencyKey = globalThis.crypto?.randomUUID?.();
    if (!idempotencyKey) {
      setErrorText("A secure order identifier is unavailable. Submission is blocked.");
      return;
    }
    const request = requestFor(idempotencyKey);
    const identity = riskIdentity(request);
    const currentTicketIdentity = ticketIdentity(props, form);
    setPreparing(true);
    preparingRef.current = true;
    setErrorText(null);
    try {
      // This read supplies the required policy digest. Only PaperRiskReviewView's immediate
      // second ALLOW can enter submitFromRiskReview and create the order.
      const assessment = await assessPaperRisk(request);
      const current = currentRef.current;
      if (
        !scopeMatchesTicket(current.props.activePaperScope, current.props) ||
        current.props.trustedOperator !== true ||
        riskIdentity(requestForCurrent(current, request.request_id)) !== identity ||
        ticketIdentity(current.props, current.form) !== currentTicketIdentity
      ) return;
      setPrepared({
        request, requestIdentity: identity, ticketIdentity: currentTicketIdentity,
        idempotencyKey, policyDigest: assessment.policy_digest,
      });
      setReviewOpen(true);
    } catch (error: unknown) {
      setErrorText(fixedRiskError(error));
    } finally {
      preparingRef.current = false;
      setPreparing(false);
    }
  }

  function requestForCurrent(current: typeof currentRef.current, requestId: string): PaperRiskAssessmentRequest {
    const selectedScope = current.props.activePaperScope;
    return {
      scope: "paper",
      account_id: selectedScope?.account_id ?? "",
      request_id: requestId,
      attempt_id: `${requestId}:1`,
      strategy_id: selectedScope?.strategy_id ?? "",
      venue_id: selectedScope?.venue ?? "",
      instrument_id: selectedScope?.instrument_id ?? "",
      side: current.form.side,
      quantity: current.form.quantity,
      price: current.props.priceEvidence.price,
      contract_multiplier: current.props.instrument.contract_multiplier,
      currency: current.props.instrument.currency,
      price_source_ns: current.props.priceEvidence.price_source_ns,
      price_ingest_ns: current.props.priceEvidence.price_ingest_ns,
      price_source_id: current.props.priceEvidence.price_source_id,
    };
  }

  async function submitFromRiskReview(riskRequest: PaperRiskAssessmentRequest): Promise<void> {
    const latest = currentRef.current;
    if (
      latest.orderResult !== null ||
      latest.dispatchState === "unknown" || latest.dispatchState === "sending" ||
      inFlightRef.current
    ) return;
    await submitReviewedOrder(riskRequest, null);
  }

  async function retryExistingDraftFromRiskReview(riskRequest: PaperRiskAssessmentRequest): Promise<void> {
    const latest = currentRef.current;
    if (
      latest.orderResult === null || latest.orderResult.state !== "CREATED" ||
      latest.dispatchState !== "retryable" || inFlightRef.current ||
      evidenceRetryCountRef.current >= MAX_EVIDENCE_RETRIES
    ) return;
    evidenceRetryCountRef.current += 1;
    await submitReviewedOrder(riskRequest, latest.orderResult);
  }

  async function submitReviewedOrder(
    riskRequest: PaperRiskAssessmentRequest,
    existingDraft: PaperOrderSnapshot | null,
  ): Promise<void> {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    let dispatchAttempted = false;
    setErrorText(null);
    setDispatchState("sending");
    try {
      const current = currentRef.current;
      const intent = current.prepared;
      if (
        intent === null || intent.requestIdentity !== riskIdentity(riskRequest) ||
        intent.requestIdentity !== riskIdentity(intent.request) ||
        intent.ticketIdentity !== ticketIdentity(current.props, current.form) ||
        !current.props.trustedOperator || !scopeMatchesTicket(current.props.activePaperScope, current.props)
      ) {
        setErrorText("The order or active paper scope changed. Review the order again before submitting.");
        setDispatchState("idle");
        setReviewOpen(false);
        return;
      }
      const createRequest: PaperOrderCreateRequest = {
        environment: PAPER_ORDER_ENVIRONMENT,
        account_id: riskRequest.account_id,
        venue: riskRequest.venue_id,
        instrument_id: riskRequest.instrument_id,
        native_contract_id: current.props.instrument.native_contract_id,
        side: riskRequest.side,
        quantity: riskRequest.quantity,
        order_type: current.form.orderType,
        time_in_force: current.form.timeInForce,
        intent_idempotency_key: intent.idempotencyKey,
        attempt: 1,
        strategy_id: riskRequest.strategy_id,
        risk_policy_digest: intent.policyDigest,
        ...(current.form.orderType === "LIMIT" ? { limit_price: current.form.limitPrice } : {}),
        ...(current.form.timeInForce === "GTD" ? { expires_at: new Date(current.form.expiresAt).toISOString() } : {}),
      };
      let createdOrder: PaperOrderSnapshot;
      if (existingDraft !== null) {
        createdOrder = existingDraft;
      } else {
        const created = await api.createOrder(createRequest);
        if (!created.ok) {
          setErrorText(ORDER_ERROR_TEXT[created.error].text);
          setDispatchState(orderOutcomeMayBeUnknown(created.error) ? "unknown" : "idle");
          setReviewOpen(false);
          return;
        }
        createdOrder = created.data;
        setOrderResult(createdOrder);
      }
      if (createdOrder.state !== "CREATED" || createdOrder.submit_attempted) {
        setErrorText("The created order is not in a submittable state. Check order status before dispatch.");
        setDispatchState("idle");
        setReviewOpen(false);
        return;
      }
      const afterCreate = currentRef.current;
      if (
        afterCreate.props.trustedOperator !== true ||
        !scopeMatchesTicket(afterCreate.props.activePaperScope, afterCreate.props) ||
        intent.ticketIdentity !== ticketIdentity(afterCreate.props, afterCreate.form)
      ) {
        setErrorText("The active scope changed after the draft was recorded. Check order status; no dispatch was attempted.");
        setDispatchState("idle");
        setReviewOpen(false);
        return;
      }
      const postCreateAssessment = await assessPaperRisk(riskRequest);
      const afterRisk = currentRef.current;
      if (
        afterRisk.props.trustedOperator !== true ||
        !scopeMatchesTicket(afterRisk.props.activePaperScope, afterRisk.props) ||
        intent.ticketIdentity !== ticketIdentity(afterRisk.props, afterRisk.form)
      ) {
        setErrorText("The active scope or order changed during the final risk check. Dispatch was blocked; check order status.");
        setDispatchState("idle");
        setReviewOpen(false);
        return;
      }
      if (
        postCreateAssessment.decision !== "ALLOW" ||
        postCreateAssessment.reason_codes.length !== 1 ||
        postCreateAssessment.reason_codes[0] !== "within_hard_limits" ||
        postCreateAssessment.policy_digest !== intent.policyDigest
      ) {
        setErrorText("Risk changed after the order was recorded. Dispatch was blocked; review current risk and check order status.");
        setDispatchState("idle");
        setReviewOpen(false);
        return;
      }
      dispatchAttempted = true;
      const dispatched = await api.submitOrder(createdOrder.order_id, {
        environment: "paper",
        account_id: createdOrder.account_id,
        venue: createdOrder.venue,
        instrument_id: createdOrder.instrument_id,
        strategy_id: createdOrder.strategy_id,
      });
      if (!dispatched.ok) {
        setErrorText(ORDER_ERROR_TEXT[dispatched.error].text);
        setDispatchState(dispatched.error === "EVIDENCE_UNAVAILABLE"
          ? evidenceRetryCountRef.current < MAX_EVIDENCE_RETRIES ? "retryable" : "retry_exhausted"
          : orderOutcomeMayBeUnknown(dispatched.error) ? "unknown" : "idle");
        if (dispatched.error === "EVIDENCE_UNAVAILABLE" && evidenceRetryCountRef.current >= MAX_EVIDENCE_RETRIES) {
          setErrorText("Paper evidence remained unavailable after the retry limit. Check order status before another action.");
        }
        setReviewOpen(false);
        return;
      }
      setOrderResult(dispatched.data);
      setDispatchState("sent");
      setReviewOpen(false);
    } catch (error: unknown) {
      setErrorText(error instanceof PaperRiskAssessmentError
        ? fixedRiskError(error)
        : "The order response could not be verified. Check order status before retrying.");
      setDispatchState(dispatchAttempted ? "unknown" : "idle");
      setReviewOpen(false);
    } finally {
      inFlightRef.current = false;
    }
  }

  const quantityInvalid = form.quantity !== "" && !validPositiveDecimal(form.quantity);
  const limitInvalid = form.orderType === "LIMIT" && form.limitPrice !== "" && !validPositiveDecimal(form.limitPrice);
  const expiryInvalid = form.timeInForce === "GTD" && form.expiresAt !== "" && !Number.isFinite(Date.parse(form.expiresAt));
  const canReview = validPositiveDecimal(form.quantity) &&
    (form.orderType !== "LIMIT" || validPositiveDecimal(form.limitPrice)) &&
    (form.timeInForce !== "GTD" || Number.isFinite(Date.parse(form.expiresAt))) &&
    !preparing && !inFlightRef.current && orderResult === null && dispatchState !== "unknown";
  const orderLocked = preparing || inFlightRef.current || orderResult !== null || dispatchState === "unknown";

  return (
    <section aria-label="Paper order ticket">
      <h2>Paper order ticket</h2>
      <p>Environment: PAPER (fixed).</p>
      <form onSubmit={(event) => { event.preventDefault(); void openReview(); }} noValidate>
        <label htmlFor="paper-ticket-side">Side</label>
        <select id="paper-ticket-side" value={form.side} disabled={orderLocked} onChange={(event) => handleFormChange({ ...form, side: event.target.value as FormState["side"] })}>
          <option value="BUY">Buy</option><option value="SELL">Sell</option>
        </select>
        <label htmlFor="paper-ticket-quantity">Quantity</label>
        <input id="paper-ticket-quantity" inputMode="decimal" value={form.quantity} disabled={orderLocked} aria-invalid={quantityInvalid} onChange={(event) => handleFormChange({ ...form, quantity: event.target.value })} />
        {quantityInvalid && <p role="alert">Enter a positive quantity using plain decimal notation.</p>}
        <label htmlFor="paper-ticket-order-type">Order type</label>
        <select id="paper-ticket-order-type" value={form.orderType} disabled={orderLocked} onChange={(event) => handleFormChange({ ...form, orderType: event.target.value as FormState["orderType"] })}>
          <option value="MARKET">Market</option><option value="LIMIT">Limit</option>
        </select>
        {form.orderType === "LIMIT" && <>
          <label htmlFor="paper-ticket-limit-price">Limit price</label>
          <input id="paper-ticket-limit-price" inputMode="decimal" value={form.limitPrice} disabled={orderLocked} aria-invalid={limitInvalid} onChange={(event) => handleFormChange({ ...form, limitPrice: event.target.value })} />
          {limitInvalid && <p role="alert">Enter a positive limit price using plain decimal notation.</p>}
        </>}
        <label htmlFor="paper-ticket-time-in-force">Time in force</label>
        <select id="paper-ticket-time-in-force" value={form.timeInForce} disabled={orderLocked} onChange={(event) => handleFormChange({ ...form, timeInForce: event.target.value as FormState["timeInForce"] })}>
          <option value="DAY">Day</option><option value="GTC">Good till canceled</option><option value="GTD">Good till date</option>
        </select>
        {form.timeInForce === "GTD" && <>
          <label htmlFor="paper-ticket-expires-at">Expiry</label>
          <input id="paper-ticket-expires-at" type="datetime-local" value={form.expiresAt} disabled={orderLocked} aria-invalid={expiryInvalid} onChange={(event) => handleFormChange({ ...form, expiresAt: event.target.value })} />
          {expiryInvalid && <p role="alert">Enter a valid expiry for a GTD order.</p>}
        </>}
        <button type="submit" disabled={!canReview}>
          {preparing ? "Checking risk…" : "Review paper order"}
        </button>
      </form>
      {errorText !== null && <p role="alert">{errorText}</p>}
      {dispatchState === "sending" && <p role="status">Submitting the paper order.</p>}
      {dispatchState === "unknown" && <p role="status">Submission outcome is unknown. Check order status before taking another action.</p>}
      {dispatchState === "retry_exhausted" && <p role="status">The evidence retry limit was reached. Check order status before taking another action.</p>}
      {dispatchState === "retryable" && orderResult?.state === "CREATED" && prepared !== null && (
        <button type="button" onClick={() => setReviewOpen(true)}>
          Recheck risk and retry this draft
        </button>
      )}
      {orderResult !== null && dispatchState !== "sent" && <p role="status">Draft order {safeOrderIdLabel(orderResult.order_id)} is {orderResult.state}; broker dispatch is not confirmed.</p>}
      {dispatchState === "sent" && orderResult !== null && <p role="status">Paper order {safeOrderIdLabel(orderResult.order_id)} is {orderResult.state}.</p>}
      {reviewOpen && prepared !== null && (
        <PaperRiskReviewView
          open={reviewOpen}
          request={prepared.request}
          onClose={() => setReviewOpen(false)}
          onSubmit={dispatchState === "retryable" ? retryExistingDraftFromRiskReview : submitFromRiskReview}
        />
      )}
    </section>
  );
}

export default PaperOrderTicketView;
