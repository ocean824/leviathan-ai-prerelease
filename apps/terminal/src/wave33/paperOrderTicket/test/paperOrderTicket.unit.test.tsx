import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createPaperOrderTicketApi,
  PAPER_ORDER_CREATE_PATH,
  type PaperOrderCreateRequest,
  type PaperOrderSnapshot,
  type PaperOrderTicketApi,
} from "../api";
import { PaperOrderTicketView, type PaperOrderTicketViewProps } from "../PaperOrderTicketView";

const SCOPE = {
  environment: "paper" as const,
  account_id: "paper-account",
  venue: "SIM",
  instrument_id: "ES-TEST",
  strategy_id: "strategy-test",
  active: true as const,
};
const SNAPSHOT: PaperOrderSnapshot = {
  order_id: "550e8400e29b41d4a716446655440000",
  state: "CREATED",
  version: 1,
  environment: "paper",
  account_id: SCOPE.account_id,
  venue: SCOPE.venue,
  instrument_id: SCOPE.instrument_id,
  strategy_id: SCOPE.strategy_id,
  filled_quantity: "0",
  venue_order_id: null,
  discrepancies: [],
  submit_attempted: false,
  cancel_attempted: false,
};

function response(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response;
}

function createRequest(overrides: Partial<PaperOrderCreateRequest> = {}): PaperOrderCreateRequest {
  return {
    environment: "paper",
    account_id: SCOPE.account_id,
    venue: SCOPE.venue,
    instrument_id: SCOPE.instrument_id,
    native_contract_id: "native-es-test",
    side: "BUY",
    quantity: "2",
    order_type: "MARKET",
    time_in_force: "DAY",
    intent_idempotency_key: "01234567-89ab-cdef-0123-456789abcdef",
    attempt: 1,
    strategy_id: SCOPE.strategy_id,
    risk_policy_digest: "a1".repeat(32),
    ...overrides,
  };
}

function viewProps(overrides: Partial<PaperOrderTicketViewProps> = {}): PaperOrderTicketViewProps {
  return {
    trustedOperator: true,
    activePaperScope: SCOPE,
    instrument: { native_contract_id: "native-es-test", contract_multiplier: "50", currency: "USD" },
    priceEvidence: {
      price: "100.25", price_source_ns: 1_700_000_000_000_000_000,
      price_ingest_ns: 1_700_000_000_010_000_000, price_source_id: "synthetic-test-mark",
    },
    ...overrides,
  };
}

const riskAllow = {
  scope: "paper",
  assessment_kind: "preview",
  decision: "ALLOW",
  assessment_time_ns: 1_700_000_000_020_000_000,
  policy_version: 1,
  policy_revisions: ["paper-v1"],
  policy_digest: "a1".repeat(32),
  reason_codes: ["within_hard_limits"],
  evidence_digest: "b2".repeat(32),
  approval_issued: false,
  order_submitted: false,
};

afterEach(() => vi.unstubAllGlobals());

describe("paper order ticket API", () => {
  it("posts only the fixed paper order schema and validates the scoped response", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(SNAPSHOT, 201));
    const api = createPaperOrderTicketApi(fetcher as unknown as typeof fetch);
    const request = createRequest();

    const result = await api.createOrder(request);

    expect(result).toEqual({ ok: true, data: SNAPSHOT });
    expect(fetcher).toHaveBeenCalledWith(PAPER_ORDER_CREATE_PATH, expect.objectContaining({
      method: "POST", credentials: "same-origin", cache: "no-store",
    }));
    const sent = JSON.parse(String(fetcher.mock.calls[0]?.[1]?.body)) as Record<string, unknown>;
    expect(sent.environment).toBe("paper");
    expect(Object.keys(sent).sort()).toEqual([
      "account_id", "attempt", "environment", "instrument_id", "intent_idempotency_key",
      "native_contract_id", "order_type", "quantity", "risk_policy_digest", "side",
      "strategy_id", "time_in_force", "venue",
    ]);
    expect(sent).not.toHaveProperty("provider");
  });

  it("rejects a crafted non-paper request without network access", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(undefined));
    const api = createPaperOrderTicketApi(fetcher as unknown as typeof fetch);
    const result = await api.createOrder(createRequest({ environment: "live" } as unknown as PaperOrderCreateRequest));
    expect(result).toEqual({ ok: false, error: "INVALID_ORDER_REQUEST" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    [403, "ACTIVATION_DISABLED"], [409, "IDEMPOTENCY_CONFLICT"], [422, "INVALID_QUANTITY"],
  ])("maps HTTP %s to a fixed code without returning raw provider text", async (status, detail) => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({ detail, provider: "private-canary" }, status));
    const result = await createPaperOrderTicketApi(fetcher as unknown as typeof fetch).createOrder(createRequest());
    expect(result).toEqual({ ok: false, error: detail });
    expect(JSON.stringify(result)).not.toContain("private-canary");
  });

  it("rejects a response for a different scope and submits only to the existing order path", async () => {
    const fetcher = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response(SNAPSHOT));
    fetcher.mockResolvedValueOnce(response({ ...SNAPSHOT, account_id: "other-account" }, 201));
    fetcher.mockResolvedValueOnce(response(SNAPSHOT));
    const api = createPaperOrderTicketApi(fetcher as unknown as typeof fetch);
    expect(await api.createOrder(createRequest())).toEqual({ ok: false, error: "INVALID_RESPONSE" });
    expect((await api.submitOrder(SNAPSHOT.order_id)).ok).toBe(true);
    expect(fetcher.mock.calls[1]?.[0]).toBe(`${PAPER_ORDER_CREATE_PATH}/${SNAPSHOT.order_id}/submit`);
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({ method: "POST", cache: "no-store" });
  });
});

describe("PaperOrderTicketView", () => {
  it("hides the CTA without trusted operator evidence or an exact active paper scope", () => {
    const client = { createOrder: vi.fn(), submitOrder: vi.fn() } as unknown as PaperOrderTicketApi;
    const { rerender } = render(<PaperOrderTicketView {...viewProps({ trustedOperator: false, client })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ activePaperScope: null, client })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ activePaperScope: { ...SCOPE, active: false } as unknown as typeof SCOPE, client })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
  });

  it("requires fresh ALLOW before create and again before dispatch", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(SNAPSHOT, 201))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ ...SNAPSHOT, state: "SUBMITTING", submit_attempted: true }));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    const { container } = render(<PaperOrderTicketView {...viewProps()} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/paper order 550e8400e29b41d4a716446655440000 is SUBMITTING/i);

    expect(fetcher).toHaveBeenCalledTimes(6);
    expect(fetcher.mock.calls.slice(0, 3).map(([url]) => url)).toEqual([
      "/api/paper/risk/assessment/v1/preview", "/api/paper/risk/assessment/v1/preview", "/api/paper/risk/assessment/v1/preview",
    ]);
    const createCall = fetcher.mock.calls[3];
    expect(createCall?.[0]).toBe("/api/orders");
    const body = JSON.parse(String(createCall?.[1]?.body)) as Record<string, unknown>;
    expect(body.environment).toBe("paper");
    expect(body.risk_policy_digest).toBe("a1".repeat(32));
    expect(body).not.toHaveProperty("provider");
    expect(fetcher.mock.calls[4]?.[0]).toBe("/api/paper/risk/assessment/v1/preview");
    expect(fetcher.mock.calls[5]?.[0]).toBe(`/api/orders/${SNAPSHOT.order_id}/submit`);

    fireEvent.submit(container.querySelector("form") as HTMLFormElement);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(6));
    expect(screen.queryByRole("dialog", { name: "Paper risk review" })).toBeNull();
  });

  it("ignores forced form submits after an ambiguous create outcome", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ detail: "UPSTREAM_TIMEOUT" }, 503));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    const { container } = render(<PaperOrderTicketView {...viewProps()} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/submission outcome is unknown/i);

    fireEvent.submit(container.querySelector("form") as HTMLFormElement);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(4));
    expect(screen.queryByRole("dialog", { name: "Paper risk review" })).toBeNull();
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/orders",
    ]);
  });

  it("retries a definite evidence refusal against the same created draft after fresh review", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(SNAPSHOT, 201))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ detail: "EVIDENCE_UNAVAILABLE" }, 503))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ ...SNAPSHOT, state: "SUBMITTING", submit_attempted: true }));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps()} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/evidence is temporarily unavailable/i);
    fireEvent.click(screen.getByRole("button", { name: /recheck risk and retry this draft/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/paper order 550e8400e29b41d4a716446655440000 is SUBMITTING/i);

    expect(fetcher.mock.calls.filter(([url]) => url === "/api/orders")).toHaveLength(1);
    expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith("/submit"))).toHaveLength(2);
    expect(fetcher.mock.calls.at(-1)?.[0]).toBe(`/api/orders/${SNAPSHOT.order_id}/submit`);
  });

  it("caps definite evidence retries for a created draft", async () => {
    const client = {
      createOrder: vi.fn().mockResolvedValue({ ok: true, data: SNAPSHOT }),
      submitOrder: vi.fn().mockResolvedValue({ ok: false, error: "EVIDENCE_UNAVAILABLE" }),
    } as unknown as PaperOrderTicketApi;
    const fetcher = vi.fn().mockResolvedValue(response(riskAllow));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps({ client })} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    for (let attempt = 0; attempt < 3; attempt += 1) {
      await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
      await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
      fireEvent.click(screen.getByRole("button", { name: "Submit" }));
      if (attempt < 2) {
        fireEvent.click(await screen.findByRole("button", { name: /recheck risk and retry this draft/i }));
      }
    }

    expect(await screen.findByText(/evidence retry limit was reached/i)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /recheck risk and retry this draft/i })).toBeNull();
    expect(client.createOrder).toHaveBeenCalledTimes(1);
    expect(client.submitOrder).toHaveBeenCalledTimes(3);
    expect(fetcher).toHaveBeenCalledTimes(10);
  });

  it("does not submit a created order unless the server returned the CREATED draft state", async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ ...SNAPSHOT, state: "RISK_REJECTED" }, 201));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps()} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/not in a submittable state/i);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/orders",
    ]);
  });

  it("hides the ticket for malformed host-supplied risk inputs", () => {
    const { rerender } = render(<PaperOrderTicketView {...viewProps()} />);
    expect(screen.getByRole("button", { name: /review paper order/i })).toBeTruthy();
    rerender(<PaperOrderTicketView {...viewProps({ instrument: { ...viewProps().instrument, contract_multiplier: "0" } })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ instrument: { ...viewProps().instrument, contract_multiplier: "50", currency: "usd" } })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ priceEvidence: { ...viewProps().priceEvidence, price: "0" } })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ activePaperScope: { ...SCOPE, strategy_id: "sk_live_abcdefghijklmno" } })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    rerender(<PaperOrderTicketView {...viewProps({ activePaperScope: { ...SCOPE, strategy_id: "session-momentum" } })} />);
    expect(screen.queryByRole("button", { name: /review paper order/i })).toBeNull();
    expect(screen.getByRole("alert").textContent).toMatch(/paper identifier could not be verified/i);
  });

  it("does not render credential-shaped server order identifiers", async () => {
    const unsafeId = "sk_live_abcdefghijklmno123456";
    const unsafeSnapshot = { ...SNAPSHOT, order_id: unsafeId } as PaperOrderSnapshot;
    const client = {
      createOrder: vi.fn().mockResolvedValue({ ok: true, data: unsafeSnapshot }),
      submitOrder: vi.fn().mockResolvedValue({
        ok: true, data: { ...unsafeSnapshot, state: "SUBMITTING", submit_attempted: true },
      }),
    } as unknown as PaperOrderTicketApi;
    const fetcher = vi.fn().mockResolvedValue(response(riskAllow));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps({ client })} />);

    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog", { name: "Paper risk review" })).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));

    expect(await screen.findByText(/paper order unverified order identifier is SUBMITTING/i)).toBeTruthy();
    expect(document.body.textContent).not.toContain(unsafeId);
    expect(client.submitOrder).toHaveBeenCalledTimes(1);
  });

  it("does not create an order when the immediate risk assessment denies", async () => {
    const deny = { ...riskAllow, decision: "DENY", reason_codes: ["max_daily_loss_exceeded"] };
    const fetcher = vi.fn().mockResolvedValueOnce(response(riskAllow)).mockResolvedValueOnce(response(riskAllow)).mockResolvedValueOnce(response(deny));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps()} />);
    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/submission denied/i);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });

  it("does not dispatch if the post-create risk recheck changes to DENY", async () => {
    const deny = { ...riskAllow, decision: "DENY", reason_codes: ["max_daily_loss_exceeded"] };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(SNAPSHOT, 201))
      .mockResolvedValueOnce(response(deny));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps()} />);
    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/risk changed after the order was recorded/i);
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual([
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/paper/risk/assessment/v1/preview",
      "/api/orders",
      "/api/paper/risk/assessment/v1/preview",
    ]);
  });

  it.each([
    [403, "ACTIVATION_DISABLED", /paper dispatch is inactive/i],
    [409, "IDEMPOTENCY_CONFLICT", /conflicts with a recorded request/i],
    [422, "INVALID_QUANTITY", /positive quantity/i],
  ])("shows fixed actionable order text for HTTP %s without raw detail", async (status, detail, expectedText) => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response(riskAllow))
      .mockResolvedValueOnce(response({ detail, diagnostic: "private-canary" }, status));
    vi.stubGlobal("fetch", fetcher);
    vi.stubGlobal("crypto", { randomUUID: () => "01234567-89ab-cdef-0123-456789abcdef" });
    render(<PaperOrderTicketView {...viewProps()} />);
    fireEvent.change(screen.getByLabelText("Quantity"), { target: { value: "1" } });
    fireEvent.click(screen.getByRole("button", { name: /review paper order/i }));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeTruthy());
    await waitFor(() => expect(screen.getByRole("button", { name: "Submit" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toMatch(expectedText);
    expect(document.body.textContent).not.toContain("private-canary");
  });
});
