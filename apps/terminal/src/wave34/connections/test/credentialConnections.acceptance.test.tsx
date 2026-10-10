import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialConnectionsPanel } from "../CredentialConnectionsPanel";

const DATA_SECRET = "SYNTHETIC-CONNECTION-DOM-SECRET-20261009-D8n4";
const MT5_SECRET = "SYNTHETIC-MT5-DOM-PASSWORD-20261009-J2p6";
const KALSHI_PEM = "-----BEGIN PRIVATE KEY-----\nMBJTU05USEVUSUMtS0FMU0hJLUtFWS0yMDI2MTAwOQ==\n-----END PRIVATE KEY-----\n";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

function statusRows(configured = false) {
  return json({ credentials: [
    { provider_id: "databento", environment: "DEVELOPMENT", configured, verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null },
    { provider_id: "mt5_forexcom", environment: "DEMO", configured, verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null },
    { provider_id: "kalshi", environment: "PAPER", configured, verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null },
  ] });
}

describe("CREDENTIAL-AND-DEVICE-001 write-only Connections acceptance", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("clears provider and MT5 Replace inputs and never renders their secret values", async () => {
    let saved = false;
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/connections/credentials")) return statusRows(saved);
      if (init?.method === "PUT") {
        saved = true;
        return json({ provider_id: url.includes("mt5_forexcom") ? "mt5_forexcom" : "databento", environment: url.includes("mt5_forexcom") ? "DEMO" : "DEVELOPMENT", configured: true, verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null });
      }
      return json({ provider_id: "synthetic", verified: true, error_code: null });
    });
    vi.stubGlobal("fetch", fetcher);
    render(<CredentialConnectionsPanel />);

    const dataCard = await screen.findByRole("article", { name: "Databento DEVELOPMENT credentials" });
    fireEvent.click(within(dataCard).getByRole("button", { name: "Replace" }));
    const dataInput = within(dataCard).getByLabelText("API key") as HTMLInputElement;
    fireEvent.change(dataInput, { target: { value: DATA_SECRET } });
    fireEvent.click(within(dataCard).getByRole("button", { name: "Save credential" }));
    await screen.findByText("Databento credential replaced.");
    expect(dataInput.value).toBe("");

    const mt5Card = screen.getByRole("article", { name: "FOREX.com MT5 DEMO credentials" });
    fireEvent.click(within(mt5Card).getByRole("button", { name: "Replace" }));
    fireEvent.change(within(mt5Card).getByLabelText("Server"), { target: { value: "demo.synthetic" } });
    fireEvent.change(within(mt5Card).getByLabelText("Login"), { target: { value: "synthetic-login" } });
    const password = within(mt5Card).getByLabelText("Password") as HTMLInputElement;
    fireEvent.change(password, { target: { value: MT5_SECRET } });
    fireEvent.click(within(mt5Card).getByRole("button", { name: "Save credential" }));
    await screen.findByText("FOREX.com MT5 credential replaced.");
    expect(password.value).toBe("");
    expect(document.body.textContent).not.toContain(DATA_SECRET);
    expect(document.body.textContent).not.toContain(MT5_SECRET);
    expect(document.body.textContent).not.toContain("synthetic-login");
  });

  it("uploads a Kalshi key without rendering the PEM or key material", async () => {
    let uploaded = false;
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/connections/credentials")) return statusRows(uploaded);
      if (init?.method === "PUT") {
        uploaded = true;
        return json({ provider_id: "kalshi", environment: "PAPER", configured: true, verified: false, last_tested_ns: null, last_rotated_ns: 1, error_code: null });
      }
      return json({ provider_id: "kalshi", verified: true, error_code: null });
    });
    vi.stubGlobal("fetch", fetcher);
    render(<CredentialConnectionsPanel />);
    const card = await screen.findByRole("article", { name: "Kalshi PAPER credentials" });
    fireEvent.click(within(card).getByRole("button", { name: "Replace" }));
    fireEvent.change(within(card).getByLabelText("Key ID"), { target: { value: "synthetic-kalshi-key-id" } });
    vi.stubGlobal("File", window.File);
    const file = new File([KALSHI_PEM], "synthetic-key.pem", { type: "application/x-pem-file" });
    Object.defineProperty(file, "arrayBuffer", {
      value: async () => new TextEncoder().encode(KALSHI_PEM).buffer,
    });
    class UploadFormData {
      constructor(_form: HTMLFormElement) {}
      get(name: string): FormDataEntryValue | null {
        if (name === "key_name") return "synthetic-kalshi-key-id";
        if (name === "private_key_file") return file;
        return null;
      }
    }
    vi.stubGlobal("FormData", UploadFormData as unknown as typeof FormData);
    const privateKeyInput = within(card).getByLabelText("Private key file") as HTMLInputElement;
    fireEvent.change(privateKeyInput, {
      target: { files: [file] },
    });
    fireEvent.click(within(card).getByRole("button", { name: "Save credential" }));
    await screen.findByText("Kalshi credential replaced.");
    expect(fetcher.mock.calls.some(([url, init]) => String(url).endsWith("/private-key") && init?.method === "PUT")).toBe(true);
    expect(document.body.textContent).not.toContain(KALSHI_PEM);
    expect(document.body.textContent).not.toContain("MBJTU05USEVUSUMtS0FMU0hJ");
    expect(document.body.textContent).not.toContain("synthetic-kalshi-key-id");
  });

  it("does not expose a secret-bearing server error in Connections DOM", async () => {
    const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/connections/credentials")) return statusRows(false);
      if (init?.method === "PUT") return json({ code: DATA_SECRET }, 503);
      return json({ code: "CREDENTIALS_UNAVAILABLE" }, 503);
    });
    vi.stubGlobal("fetch", fetcher);
    render(<CredentialConnectionsPanel />);
    const card = await screen.findByRole("article", { name: "Databento DEVELOPMENT credentials" });
    fireEvent.click(within(card).getByRole("button", { name: "Replace" }));
    fireEvent.change(within(card).getByLabelText("API key"), { target: { value: DATA_SECRET } });
    fireEvent.click(within(card).getByRole("button", { name: "Save credential" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toBe("Credential service is unavailable."));
    expect(document.body.textContent).not.toContain(DATA_SECRET);
  });
});
