import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  assessPaperRisk,
  PaperRiskAssessmentError,
  PAPER_RISK_ASSESSMENT_PATH,
  type PaperRiskAssessmentRequest,
} from "../api";
import { PaperRiskReviewView } from "../PaperRiskReviewView";

const request: PaperRiskAssessmentRequest = {
  scope: "paper",
  account_id: "acct-paper-test",
  request_id: "request-test",
  attempt_id: "attempt-test",
  strategy_id: "strategy-test",
  venue_id: "venue-test",
  instrument_id: "ES-TEST",
  side: "BUY",
  quantity: "1",
  price: "100.25",
  contract_multiplier: "50",
  currency: "USD",
  price_source_ns: 1_700_000_000_000_000_000,
  price_ingest_ns: 1_700_000_000_010_000_000,
  price_source_id: "synthetic-test-mark",
};

const allow = {
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

function response(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("paper risk review API", () => {
  it("posts the exact paper preview payload with no-store and same-origin credentials", async () => {
    const fetcher = vi.fn(async () => response(allow));
    await assessPaperRisk(request, fetcher as unknown as typeof fetch);

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      PAPER_RISK_ASSESSMENT_PATH,
      expect.objectContaining({
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        body: JSON.stringify(request),
      }),
    );
  });

  it("rejects invalid request scope before making a network call", async () => {
    const fetcher = vi.fn();
    await expect(
      assessPaperRisk(
        { ...request, scope: "live" } as unknown as PaperRiskAssessmentRequest,
        fetcher as unknown as typeof fetch,
      ),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("maps HTTP status to a fixed code without reading or echoing response text", async () => {
    const fetcher = vi.fn(async () => response({ detail: "private-provider-canary" }, 503));
    await expect(assessPaperRisk(request, fetcher as unknown as typeof fetch)).rejects.toMatchObject({
      code: "ASSESSMENT_UNAVAILABLE",
      message: expect.not.stringContaining("private-provider-canary"),
    });
  });

  it("rejects unknown reason codes and response fields", async () => {
    const unknownReason = vi.fn(async () =>
      response({ ...allow, reason_codes: ["provider-private-canary"] }),
    );
    await expect(
      assessPaperRisk(request, unknownReason as unknown as typeof fetch),
    ).rejects.toBeInstanceOf(PaperRiskAssessmentError);

    const extraField = vi.fn(async () => response({ ...allow, approval_token: "unexpected" }));
    await expect(
      assessPaperRisk(request, extraField as unknown as typeof fetch),
    ).rejects.toMatchObject({ code: "INVALID_RESPONSE" });
  });

  it.each([
    "buying_power_exceeded",
    "max_order_quantity_exceeded",
    "max_order_notional_exceeded",
    "max_projected_position_exceeded",
    "max_gross_exposure_exceeded",
    "max_net_exposure_exceeded",
    "max_leverage_exceeded",
    "max_daily_loss_exceeded",
    "order_rate_exceeded",
  ])("rejects ALLOW paired with denial reason %s", async (reasonCode) => {
    const fetcher = vi.fn(async () => response({ ...allow, reason_codes: [reasonCode] }));
    await expect(assessPaperRisk(request, fetcher as unknown as typeof fetch)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("rejects ALLOW with no reason codes", async () => {
    const fetcher = vi.fn(async () => response({ ...allow, reason_codes: [] }));
    await expect(assessPaperRisk(request, fetcher as unknown as typeof fetch)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });

  it("rejects ALLOW with duplicate reason codes", async () => {
    const fetcher = vi.fn(async () =>
      response({ ...allow, reason_codes: ["within_hard_limits", "within_hard_limits"] }),
    );
    await expect(assessPaperRisk(request, fetcher as unknown as typeof fetch)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });


  it("fails closed when the response claims approval or order submission", async () => {
    const fetcher = vi.fn(async () => response({ ...allow, approval_issued: true }));
    await expect(assessPaperRisk(request, fetcher as unknown as typeof fetch)).rejects.toMatchObject({
      code: "INVALID_RESPONSE",
    });
  });
});

describe("PaperRiskReviewView", () => {
  it("presents neutral hard-limit scope information and re-assesses immediately before callback", async () => {
    const fetcher = vi.fn(async () => response(allow));
    vi.stubGlobal("fetch", fetcher);
    const onSubmit = vi.fn();
    render(
      <PaperRiskReviewView
        open
        request={request}
        onClose={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    expect(await screen.findByRole("dialog")).toBeTruthy();
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/hard-limit preview only; soft limits are not evaluated here/i)).toBeTruthy();
    expect(screen.getByText(new RegExp(request.account_id))).toBeTruthy();
    expect(screen.getByRole("button", { name: /submit/i }).hasAttribute("disabled")).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(onSubmit).toHaveBeenCalledWith(request);
  });

  it("rejects ALLOW paired with a stale reason as invalid", async () => {
    const staleAllow = { ...allow, reason_codes: ["state_stale"] };
    const fetcher = vi.fn(async () => response(staleAllow));
    vi.stubGlobal("fetch", fetcher);
    const onSubmit = vi.fn();
    render(
      <PaperRiskReviewView
        open
        request={request}
        onClose={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    const submit = await screen.findByRole("button", { name: /submit/i });
    await waitFor(() => expect(submit.hasAttribute("disabled")).toBe(true));
    fireEvent.click(submit);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getAllByText(/response could not be verified/i).length).toBeGreaterThan(0);
  });

  it("blocks inconsistent ALLOW plus hard-breach reason without exposing that reason", async () => {
    const inconsistentAllow = { ...allow, reason_codes: ["max_daily_loss_exceeded"] };
    const fetcher = vi.fn(async () => response(inconsistentAllow));
    vi.stubGlobal("fetch", fetcher);
    const onSubmit = vi.fn();
    render(
      <PaperRiskReviewView
        open
        request={request}
        onClose={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    const submit = await screen.findByRole("button", { name: /submit/i });
    await waitFor(() => expect(submit.hasAttribute("disabled")).toBe(true));
    fireEvent.click(submit);
    expect(onSubmit).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain("max_daily_loss_exceeded");
    expect(document.body.textContent).not.toMatch(/exceeds the daily loss limit/i);
    expect(document.body.textContent).not.toMatch(/allows this order for review/i);
    expect(document.body.textContent).toMatch(/could not be verified|invalid response/i);
  });

  it("blocks submission if the immediate pre-submit assessment denies", async () => {
    const deny = { ...allow, decision: "DENY", reason_codes: ["price_stale"] };
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response(allow))
      .mockResolvedValueOnce(response(deny));
    vi.stubGlobal("fetch", fetcher);
    const onSubmit = vi.fn();
    render(
      <PaperRiskReviewView
        open
        request={request}
        onClose={vi.fn()}
        onSubmit={onSubmit}
      />,
    );
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: /submit/i }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /submit/i }).hasAttribute("disabled")).toBe(true),
    );
    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getAllByText(/stale assessment/i).length).toBeGreaterThan(0);
  });
});



