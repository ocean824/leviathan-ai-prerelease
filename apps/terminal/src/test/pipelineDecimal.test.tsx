import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { apiResponse } from "./fixtures/api";
import { Pipeline } from "../tabs/Pipeline";

const replayResult = {
  decision: {
    decision_id: "decision-c102",
    permission: "approve",
    direction: "long",
    confidence: "0.75",
    justification: "Synthetic replay result",
  },
  verdict: { action: "allow", reason: "synthetic" },
  final_verdict: null,
  journal_record: null,
  intent: null,
  status: "blocked" as const,
  final: false,
  audit_sink_failure: false,
  failure_reason: null,
  session: { label: "ny_overlap", quality: "0.8" },
  truth: { sentiment_modifier: "0.07" },
};

describe("Pipeline decimal string API values", () => {
  beforeEach(() => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(apiResponse(replayResult));
  });

  it("renders canonical confidence and quality strings safely", async () => {
    render(<Pipeline />);
    fireEvent.click(screen.getByRole("button", { name: "RUN NQ BREAKOUT REPLAY" }));

    expect(await screen.findByText("75%")).toBeTruthy();
    expect(screen.getByText("0.8")).toBeTruthy();
  });
});
