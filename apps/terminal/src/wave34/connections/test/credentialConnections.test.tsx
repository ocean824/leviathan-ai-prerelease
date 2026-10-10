import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialConnectionsPanel } from "../CredentialConnectionsPanel";

const SENTINEL = "SYNTHETIC-WRITE-ONLY-SECRET-7654321";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("CredentialConnectionsPanel", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("clears a replace input immediately and never renders the sentinel", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/connections/credentials")) return json({ credentials: [] });
      if (init?.method === "PUT") return json({ provider_id: "databento", environment: "DEVELOPMENT", configured: true,
        verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null });
      return json({ provider_id: "databento", verified: true, error_code: null });
    });
    vi.stubGlobal("fetch", fetcher);
    render(<CredentialConnectionsPanel />);
    const card = await screen.findByRole("article", { name: "Databento DEVELOPMENT credentials" });
    const replace = within(card).getByRole("button", { name: "Replace" });
    fireEvent.click(replace);
    const input = within(card).getByLabelText("API key") as HTMLInputElement;
    fireEvent.change(input, { target: { value: SENTINEL } });
    fireEvent.click(within(card).getByRole("button", { name: "Save credential" }));
    expect(input.value).toBe("");
    await screen.findByText("Databento credential replaced.");
    expect(document.body.textContent).not.toContain(SENTINEL);
    expect(fetcher.mock.calls.some(([, init]) => String(init?.body).includes(SENTINEL))).toBe(true);
    await waitFor(() => expect(document.body.textContent).not.toContain(SENTINEL));
  });

  it("requires an in-app confirmation before removing a credential", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/connections/credentials")) return json({ credentials: [
        { provider_id: "databento", environment: "DEVELOPMENT", configured: true, verified: true,
          last_tested_ns: 1, last_rotated_ns: 1, error_code: null },
      ] });
      if (String(input).endsWith("/remove-confirmation")) {
        return json({ confirmation_token: "synthetic-confirmation-token-0123456789", expires_at_ns: "1800000000060000000" });
      }
      if (init?.method === "DELETE") return json({ provider_id: "databento", removed: true });
      return json({ provider_id: "databento", verified: true, error_code: null });
    });
    vi.stubGlobal("fetch", fetcher);
    render(<CredentialConnectionsPanel />);
    const card = await screen.findByRole("article", { name: "Databento DEVELOPMENT credentials" });
    fireEvent.click(within(card).getByRole("button", { name: "Remove" }));
    expect(screen.getByRole("dialog", { name: "Confirm credential removal" })).toBeTruthy();
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "DELETE")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Confirm removal" }));
    await screen.findByText("Credential removed.");
    const confirmationCall = fetcher.mock.calls.find(([input]) => String(input).endsWith("/remove-confirmation"));
    const deleteCall = fetcher.mock.calls.find(([, init]) => init?.method === "DELETE");
    expect(confirmationCall).toBeTruthy();
    expect(deleteCall).toBeTruthy();
    expect(JSON.parse(String(deleteCall?.[1]?.body)).confirmation_token).toBe("synthetic-confirmation-token-0123456789");
    expect(document.body.textContent).not.toContain("synthetic-confirmation-token");
  });
});
