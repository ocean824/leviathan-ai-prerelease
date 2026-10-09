import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { apiResponse } from "./fixtures/api";

const ENDPOINT = "/api/live-trading/credentials";
const SECRET = "SYNTHETIC-not-a-secret-0001";

function configuredResponse() {
  return {
    profiles: [{
      provider: "ALPACA",
      environment: "PAPER",
      profile: "default",
      configured: { key_id: true, secret_key: true },
      updated_at: "2026-10-06T12:00:00Z",
      verification: "NOT_TESTED",
      secret_key: SECRET,
      token: SECRET,
    }],
    unexpected_secret: SECRET,
  };
}

function openLiveTrading() {
  window.history.replaceState({}, "", "/#LIVE");
  render(<App />);
}

function mockCredentialApi(putStatus = 200) {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === ENDPOINT && (!init?.method || init.method === "GET")) {
      return apiResponse(configuredResponse());
    }
    if (url.startsWith(`${ENDPOINT}/`) && init?.method === "PUT") {
      return apiResponse(
        putStatus === 200
          ? { provider: "ALPACA", environment: "PAPER", profile: "default", revision: 2, updated_at: "2026-10-06T12:01:00Z", configured: { key_id: true, secret_key: true }, unexpected_secret: SECRET }
          : { code: "INVALID_FIELDS", detail: SECRET },
        putStatus,
      );
    }
    return apiResponse({ detail: "Unavailable" }, 503);
  });
  return requests;
}

describe("Live Trading credential configurations", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("registers LIVE while preserving the existing navigation codes", async () => {
    mockCredentialApi();
    openLiveTrading();

    expect(await screen.findByRole("heading", { name: "Live Trading" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /LIVE Live Trading/i })).toBeTruthy();
    for (const code of ["CC", "JRNL", "RISK", "GENOME", "PIPE", "HELP"]) {
      expect(screen.getByRole("tab", { name: new RegExp(code) })).toBeTruthy();
    }
  });

  it("shows only sanitized status metadata and never renders values returned by the API", async () => {
    mockCredentialApi();
    openLiveTrading();

    const status = await screen.findAllByText(/Configured, updated .*verification NOT_TESTED/);
    expect(status.length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain(SECRET);
    expect(document.body.textContent).not.toMatch(/\bverified\b|\bconnected\b/i);
  });

  it("clears password inputs on success and keeps the secret out of the DOM and browser storage", async () => {
    const requests = mockCredentialApi();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca PAPER credential form" });
    const keyId = within(form).getByLabelText("Key ID") as HTMLInputElement;
    const secretKey = within(form).getByLabelText("Secret key") as HTMLInputElement;
    expect(keyId.type).toBe("password");
    expect(keyId.autocomplete).toBe("new-password");
    expect(secretKey.type).toBe("password");
    expect(secretKey.autocomplete).toBe("new-password");
    fireEvent.change(keyId, { target: { value: SECRET } });
    fireEvent.change(secretKey, { target: { value: "SYNTHETIC-secret-0002" } });
    fireEvent.submit(form);

    expect(await within(form).findByText(/Configuration saved/)).toBeTruthy();
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");
    expect(document.body.textContent).not.toContain(SECRET);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);

    const put = requests.find((request) => request.init?.method === "PUT");
    expect(put?.url).toBe(`${ENDPOINT}/ALPACA/PAPER/default`);
    expect(put?.url).not.toContain(SECRET);
    expect(JSON.parse(String(put?.init?.body))).toMatchObject({ key_id: SECRET, secret_key: "SYNTHETIC-secret-0002" });
  });

  it("ignores same-tick re-entrant submits and sends only one full payload", async () => {
    const requests = mockCredentialApi();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca PAPER credential form" });
    const keyId = within(form).getByLabelText("Key ID") as HTMLInputElement;
    const secretKey = within(form).getByLabelText("Secret key") as HTMLInputElement;
    fireEvent.change(keyId, { target: { value: "SYNTHETIC-key-0003" } });
    fireEvent.change(secretKey, { target: { value: "SYNTHETIC-secret-0004" } });

    fireEvent.submit(form);
    fireEvent.submit(form);

    const puts = requests.filter((request) => request.init?.method === "PUT");
    expect(puts).toHaveLength(1);
    expect(JSON.parse(String(puts[0]?.init?.body))).toMatchObject({
      key_id: "SYNTHETIC-key-0003",
      secret_key: "SYNTHETIC-secret-0004",
    });
    expect(await within(form).findByText(/Configuration saved/)).toBeTruthy();
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");
  });
  it("submits valid IBKR PAPER and LIVE forms, clears inputs and rejects nonnumeric values", async () => {
    const requests = mockCredentialApi();
    openLiveTrading();

    const puts = () => requests.filter((request) => request.init?.method === "PUT");
    const configurations = [
      { environment: "PAPER" as const, hostValue: "127.0.0.1", portValue: "1" },
      { environment: "LIVE" as const, hostValue: "::1", portValue: "65535" },
    ];

    for (const [index, configuration] of configurations.entries()) {
      const form = screen.getByRole("form", {
        name: "Interactive Brokers " + configuration.environment + " credential form",
      });
      const host = within(form).getByLabelText("Loopback host") as HTMLInputElement;
      const port = within(form).getByLabelText("Port") as HTMLInputElement;
      const clientId = within(form).getByLabelText("Client ID") as HTMLInputElement;
      const accountId = within(form).getByLabelText("Account ID") as HTMLInputElement;
      fireEvent.change(host, { target: { value: configuration.hostValue } });
      fireEvent.change(port, { target: { value: configuration.portValue } });
      fireEvent.change(clientId, { target: { value: "0" } });
      fireEvent.change(accountId, { target: { value: "SYNTHETIC-account-0001" } });
      if (configuration.environment === "LIVE") {
        fireEvent.change(within(form).getByLabelText("Type LIVE to confirm"), { target: { value: "LIVE" } });
      }

      fireEvent.submit(form);
      await waitFor(() => expect(puts()).toHaveLength(index + 1));

      const payload = JSON.parse(String(puts()[index]?.init?.body));
      expect(puts()[index]?.url).toBe(ENDPOINT + "/IBKR/" + configuration.environment + "/default");
      expect(payload).toMatchObject({
        host: configuration.hostValue,
        port: Number(configuration.portValue),
        client_id: 0,
        account_id: "SYNTHETIC-account-0001",
      });
      if (configuration.environment === "LIVE") expect(payload.confirm_environment).toBe("LIVE");
      expect(host.value).toBe("");
      expect(port.value).toBe("");
      expect(clientId.value).toBe("");
      expect(accountId.value).toBe("");
    }

    const paperForm = screen.getByRole("form", { name: "Interactive Brokers PAPER credential form" });
    const host = within(paperForm).getByLabelText("Loopback host");
    const port = within(paperForm).getByLabelText("Port");
    const clientId = within(paperForm).getByLabelText("Client ID");
    const accountId = within(paperForm).getByLabelText("Account ID");
    const fill = (portValue: string, clientIdValue: string) => {
      fireEvent.change(host, { target: { value: "127.0.0.1" } });
      fireEvent.change(port, { target: { value: portValue } });
      fireEvent.change(clientId, { target: { value: clientIdValue } });
      fireEvent.change(accountId, { target: { value: "SYNTHETIC-account-0001" } });
    };

    fill("not-a-number", "0");
    fireEvent.submit(paperForm);
    expect((await within(paperForm).findByRole("alert")).textContent).toContain("valid loopback host");
    expect(puts()).toHaveLength(2);

    fill("7497", "not-a-number");
    fireEvent.submit(paperForm);
    expect((await within(paperForm).findByRole("alert")).textContent).toContain("valid loopback host");
    expect(puts()).toHaveLength(2);
  });
  it("clears password inputs after an API error without displaying response text", async () => {
    mockCredentialApi(422);
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca PAPER credential form" });
    const keyId = within(form).getByLabelText("Key ID") as HTMLInputElement;
    fireEvent.change(keyId, { target: { value: SECRET } });
    fireEvent.submit(form);

    expect((await within(form).findByRole("alert")).textContent).toContain("Configuration was not saved");
    expect(keyId.value).toBe("");
    expect(document.body.textContent).not.toContain(SECRET);
    expect(document.body.textContent).not.toContain("INVALID_FIELDS");
  });

  it("requires typed LIVE confirmation and clears secret fields even on local validation errors", async () => {
    const requests = mockCredentialApi();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca LIVE credential form" });
    const keyId = within(form).getByLabelText("Key ID") as HTMLInputElement;
    fireEvent.change(keyId, { target: { value: SECRET } });
    fireEvent.submit(form);

    expect((await within(form).findByRole("alert")).textContent).toContain("Type LIVE to confirm");
    expect(keyId.value).toBe("");
    expect(requests.some((request) => request.init?.method === "PUT" && request.url.endsWith("/ALPACA/LIVE/default"))).toBe(false);
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("mirrors the closed server ID syntax and rejects reserved MCP IDs", async () => {
    const requests = mockCredentialApi();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "MCP server PAPER credential form" });
    const serverId = within(form).getByLabelText("Server name / ID");
    const token = within(form).getByLabelText("Access token") as HTMLInputElement;
    fireEvent.change(serverId, { target: { value: "COM1" } });
    fireEvent.change(token, { target: { value: SECRET } });
    fireEvent.submit(form);

    expect((await within(form).findByRole("alert")).textContent).toMatch(/reserved device names/i);
    expect(token.value).toBe("");
    expect(requests.some((request) => request.init?.method === "PUT")).toBe(false);
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it("shows unavailable status with Retry when the API cannot be reached", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(apiResponse({ detail: "RAW-ERROR-DETAIL-MARKER" }, 503));
    openLiveTrading();

    const credentialStatus = screen.getByRole("region", { name: "Credential status" });
    await waitFor(() => expect(within(credentialStatus).getByRole("alert").textContent).toContain("Credential status unavailable"));
    expect(within(credentialStatus).getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(document.body.textContent).not.toContain("RAW-ERROR-DETAIL-MARKER");
  });
});
