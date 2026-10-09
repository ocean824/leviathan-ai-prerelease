import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import { REGISTRY, resolveHash } from "../navigation/registry";
import { parseCommand } from "../navigation/commands";
import { apiResponse } from "./fixtures/api";
import {
  credentialErrorResponse,
  credentialFixture,
  credentialStatusResponse,
  credentialWriteResponse,
} from "./fixtures/liveTrading";

type CapturedRequest = { url: string; init?: RequestInit };

function mockCredentialApi(options: { statusStatus?: number; putStatus?: number } = {}) {
  const requests: CapturedRequest[] = [];
  let statusReads = 0;
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input);
    requests.push({ url, init });
    if (url === credentialFixture.endpoint && (!init?.method || init.method === "GET")) {
      statusReads += 1;
      return options.statusStatus && options.statusStatus >= 400
        ? apiResponse(credentialErrorResponse(), options.statusStatus)
        : apiResponse(credentialStatusResponse());
    }
    if (url.startsWith(credentialFixture.endpoint + "/") && init?.method === "PUT") {
      return apiResponse(
        options.putStatus && options.putStatus >= 400
          ? credentialErrorResponse()
          : credentialWriteResponse(),
        options.putStatus ?? 200,
      );
    }
    return apiResponse({ detail: "Unexpected synthetic route" }, 503);
  });
  return { requests, statusReadCount: () => statusReads };
}

function openLiveTrading() {
  window.history.replaceState({}, "", "/#LIVE");
  render(<App />);
}

function captureConsole() {
  const entries: unknown[] = [];
  const spies = [
    vi.spyOn(console, "debug").mockImplementation((...args) => entries.push(...args)),
    vi.spyOn(console, "info").mockImplementation((...args) => entries.push(...args)),
    vi.spyOn(console, "log").mockImplementation((...args) => entries.push(...args)),
    vi.spyOn(console, "warn").mockImplementation((...args) => entries.push(...args)),
    vi.spyOn(console, "error").mockImplementation((...args) => entries.push(...args)),
  ];
  return { entries, spies };
}

function serializedConsole(entries: readonly unknown[]) {
  return entries.map((entry) => {
    try {
      return JSON.stringify(entry);
    } catch {
      return String(entry);
    }
  }).join(" ");
}

function storageText() {
  const pairs = (storage: Storage) =>
    Array.from({ length: storage.length }, (_, index) => {
      const key = storage.key(index) ?? "";
      return key + "=" + (storage.getItem(key) ?? "");
    });
  return [...pairs(localStorage), ...pairs(sessionStorage)].join(" ");
}

function expectNoSecretLeak(
  secrets: readonly string[],
  requests: readonly CapturedRequest[],
  consoleEntries: readonly unknown[],
) {
  const rendered = document.documentElement.outerHTML + " " + (document.body.textContent ?? "");
  const stored = storageText();
  const logged = serializedConsole(consoleEntries);
  for (const secret of secrets) {
    expect(rendered).not.toContain(secret);
    expect(stored).not.toContain(secret);
    expect(logged).not.toContain(secret);
    expect(window.location.href).not.toContain(secret);
    for (const request of requests) {
      expect(request.url).not.toContain(secret);
      expect(new URL(request.url, window.location.href).search).toBe("");
    }
  }
}

function fillAlpacaPaperSecrets(form: HTMLElement) {
  const keyId = within(form).getByLabelText("Key ID") as HTMLInputElement;
  const secretKey = within(form).getByLabelText("Secret key") as HTMLInputElement;
  fireEvent.change(keyId, { target: { value: credentialFixture.secrets.keyId } });
  fireEvent.change(secretKey, { target: { value: credentialFixture.secrets.secretKey } });
  return { keyId, secretKey };
}

describe("independent CRED-UI-001b Live Trading acceptance", () => {
  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("registers LIVE without changing any C-104 navigation codes", async () => {
    mockCredentialApi();
    openLiveTrading();

    expect(await screen.findByRole("heading", { name: "Live Trading" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: /LIVE Live Trading/i })).toBeTruthy();
    expect(REGISTRY.filter((entry) => entry.code === "LIVE")).toHaveLength(1);
    expect(REGISTRY.find((entry) => entry.code === "LIVE")?.kind).toBe("tab");
    const c104Codes = [
      "CC",
      "INTEL",
      "QR",
      "GP",
      "HP",
      "OMON",
      "CURV",
      "FXC",
      "WEI",
      "JRNL",
      "RISK",
      "GENOME",
      "PIPE",
      "HELP",
      "TODAY",
      "SYMBOL",
      "STRATEGY",
    ];
    expect(REGISTRY.map((entry) => entry.code)).toEqual(expect.arrayContaining([...c104Codes, "LIVE"]));
    for (const code of c104Codes) {
      expect(REGISTRY.filter((entry) => entry.code === code)).toHaveLength(1);
      expect(resolveHash(`#${code}`).code).toBe(code);
      expect(parseCommand(code)).toEqual({ type: "navigate", code });
    }
  });

  it("renders seven empty password inputs with new-password autocomplete and never prefills them", async () => {
    mockCredentialApi();
    openLiveTrading();

    await screen.findByRole("region", { name: "Credential status" });
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input[type="password"]'));
    expect(inputs).toHaveLength(7);
    for (const input of inputs) {
      expect(input.type).toBe("password");
      expect(input.autocomplete).toBe("new-password");
      expect(input.value).toBe("");
      expect(input.hasAttribute("value")).toBe(false);
    }
    expect(document.body.textContent).not.toContain(credentialFixture.responseMarkers.statusSecret);
    expect(document.body.textContent).not.toContain(credentialFixture.responseMarkers.statusToken);
  });

  it("keeps status to sanitized metadata and forces verification to NOT_TESTED", async () => {
    mockCredentialApi();
    openLiveTrading();

    const status = screen.getByRole("region", { name: "Credential status" });
    expect(await within(status).findByText(/Configured, updated .*verification NOT_TESTED/)).toBeTruthy();
    expect(status.textContent).not.toMatch(/connected|verified/i);
    expect(status.textContent).toContain("NOT_TESTED");
    for (const marker of Object.values(credentialFixture.responseMarkers)) {
      expect(document.documentElement.outerHTML).not.toContain(marker);
    }
    expect(document.body.textContent).not.toContain("87654321");
  });

  it("sends synthetic secrets only in the request body and clears them after success", async () => {
    const { requests } = mockCredentialApi();
    const consoleCapture = captureConsole();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca PAPER credential form" });
    const { keyId, secretKey } = fillAlpacaPaperSecrets(form);
    fireEvent.submit(form);

    expect(await within(form).findByText(/Configuration saved/)).toBeTruthy();
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");

    const put = requests.find((request) => request.init?.method === "PUT");
    expect(put).toBeTruthy();
    expect(put?.url).toBe(credentialFixture.profilePath);
    expect(new URL(put!.url, window.location.href).search).toBe("");
    expect(JSON.parse(String(put?.init?.body))).toEqual({
      key_id: credentialFixture.secrets.keyId,
      secret_key: credentialFixture.secrets.secretKey,
    });
    expectNoSecretLeak(
      [
        ...Object.values(credentialFixture.secrets),
        ...Object.values(credentialFixture.responseMarkers),
        "RESPONSE-PROVIDER-MARKER",
        "RESPONSE-ENVIRONMENT-MARKER",
        "87654321",
        "1999-01-01T00:00:00Z",
      ],
      requests,
      consoleCapture.entries,
    );
    expect(document.body.textContent).not.toContain("SYNTHETIC-ERROR-CODE");
    expect(consoleCapture.spies).toHaveLength(5);
  });

  it("clears every submitted password input after an API error and never echoes error data", async () => {
    const { requests } = mockCredentialApi({ putStatus: 422 });
    const consoleCapture = captureConsole();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca PAPER credential form" });
    const { keyId, secretKey } = fillAlpacaPaperSecrets(form);
    fireEvent.submit(form);

    expect((await within(form).findByRole("alert")).textContent).toContain("Configuration was not saved");
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");
    expect(document.body.textContent).not.toContain("SYNTHETIC-ERROR-CODE");
    expectNoSecretLeak(
      [
        ...Object.values(credentialFixture.secrets),
        ...Object.values(credentialFixture.responseMarkers),
      ],
      requests,
      consoleCapture.entries,
    );
  });

  it("requires typed LIVE confirmation, preserves the disabled-until-switch note, and never enables trading", async () => {
    const { requests } = mockCredentialApi();
    openLiveTrading();

    const form = screen.getByRole("form", { name: "Alpaca LIVE credential form" });
    const { keyId, secretKey } = fillAlpacaPaperSecrets(form);
    const confirmation = within(form).getByLabelText("Type LIVE to confirm") as HTMLInputElement;

    fireEvent.submit(form);
    expect((await within(form).findByRole("alert")).textContent).toContain("Type LIVE to confirm");
    expect(requests.some((request) => request.init?.method === "PUT")).toBe(false);
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");

    fireEvent.change(keyId, { target: { value: credentialFixture.secrets.liveKeyId } });
    fireEvent.change(secretKey, { target: { value: credentialFixture.secrets.liveSecretKey } });
    fireEvent.change(confirmation, { target: { value: "LIVE" } });
    fireEvent.submit(form);

    expect(await within(form).findByText(/Configuration saved/)).toBeTruthy();
    expect(confirmation.value).toBe("");
    expect(keyId.value).toBe("");
    expect(secretKey.value).toBe("");

    const livePut = requests.find((request) =>
      request.init?.method === "PUT" && request.url === credentialFixture.liveProfilePath
    );
    expect(JSON.parse(String(livePut?.init?.body))).toEqual({
      key_id: credentialFixture.secrets.liveKeyId,
      secret_key: credentialFixture.secrets.liveSecretKey,
      confirm_environment: "LIVE",
    });
    expect(screen.getByLabelText("Live trading safety").textContent).toMatch(
      /live trading stays disabled.*until risk limits are set and the operator switch is flipped/i,
    );
    expect(screen.queryByRole("switch")).toBeNull();
    expect(document.querySelector('input[type="checkbox"]')).toBeNull();
    const enableLiveButtons = screen.getAllByRole("button", { name: /enable live/i });
    expect(enableLiveButtons.length).toBeGreaterThan(0);
    expect(enableLiveButtons.every((button) => (button as HTMLButtonElement).disabled)).toBe(true);
    expect(document.body.textContent).toMatch(/execution\s+disabled/i);
    const credentialRequests = requests.filter((request) =>
      request.url === credentialFixture.endpoint ||
      request.url === credentialFixture.liveProfilePath
    );
    expect(credentialRequests.some((request) =>
      request.url === credentialFixture.endpoint && (!request.init?.method || request.init.method === "GET")
    )).toBe(true);
    expect(credentialRequests.some((request) =>
      request.url === credentialFixture.liveProfilePath && request.init?.method === "PUT"
    )).toBe(true);
    expect(requests.every((request) =>
      request.url === "/api/live-activation/status" ||
      request.url === credentialFixture.endpoint ||
      request.url === credentialFixture.liveProfilePath
    )).toBe(true);
  });

  it("shows API-down as unavailable with Retry and retries without exposing the error body", async () => {
    vi.useFakeTimers();
    const { requests, statusReadCount } = mockCredentialApi({ statusStatus: 503 });
    openLiveTrading();

    await act(async () => {
      await Promise.resolve();
      await Promise.resolve();
    });
    const status = screen.getByRole("region", { name: "Credential status" });
    expect(status.textContent).toContain("Credential status unavailable");
    expect(within(status).getByRole("button", { name: "Retry" })).toBeTruthy();
    expect(status.textContent).not.toContain(credentialFixture.responseMarkers.errorDetail);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    expect(statusReadCount()).toBeGreaterThanOrEqual(2);
    expect(requests.every((request) =>
      request.url === "/api/live-activation/status" || request.url === credentialFixture.endpoint
    )).toBe(true);
    expect(document.body.textContent).not.toContain(credentialFixture.responseMarkers.errorDetail);
    expect(storageText()).not.toContain(credentialFixture.responseMarkers.errorDetail);
  });

  it("never puts secret values in a fetch URL or query, even when status carries secret-shaped fields", async () => {
    const { requests } = mockCredentialApi();
    openLiveTrading();

    expect(await screen.findAllByText(/verification NOT_TESTED/)).not.toHaveLength(0);
    for (const request of requests) {
      expect(request.url).not.toContain(credentialFixture.responseMarkers.statusSecret);
      expect(request.url).not.toContain(credentialFixture.responseMarkers.statusToken);
      expect(new URL(request.url, window.location.href).search).toBe("");
    }
    expect(document.body.textContent).not.toContain(credentialFixture.responseMarkers.statusSecret);
    expect(document.body.textContent).not.toContain(credentialFixture.responseMarkers.statusToken);
  });
});
