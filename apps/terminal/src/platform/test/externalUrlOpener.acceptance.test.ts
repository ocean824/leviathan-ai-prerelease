import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createExternalUrlOpener } from "../externalUrlOpener";

type TauriInternals = {
  invoke?: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
};

type TauriWindow = Window & { __TAURI_INTERNALS__?: TauriInternals };

function setTauriInternals(value: TauriInternals | undefined): void {
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    configurable: true,
    value,
  });
}

describe("SHELL-OPENER-001 acceptance", () => {
  beforeEach(() => {
    delete (window as TauriWindow).__TAURI_INTERNALS__;
  });

  afterEach(() => {
    delete (window as TauriWindow).__TAURI_INTERNALS__;
    vi.restoreAllMocks();
  });

  it("fails closed in a plain browser without attempting a command", async () => {
    const opener = createExternalUrlOpener();
    expect(await opener.open(new URL("https://app.alpaca.markets/oauth"))).toBe("unavailable");
  });

  it("invokes only the desktop command with the URL as its sole argument", async () => {
    const invoke = vi.fn(async () => undefined);
    setTauriInternals({ invoke });

    const url = new URL("https://login.coinbase.com/oauth?state=synthetic");
    const opener = createExternalUrlOpener();
    expect(await opener.open(url)).toBe("opened");
    expect(invoke).toHaveBeenCalledTimes(1);
    expect(invoke).toHaveBeenCalledWith("open_external_url", { url: url.href });
  });

  it("maps command rejection to unavailable without exposing the rejection", async () => {
    const invoke = vi.fn(async () => {
      throw new Error("synthetic-browser-launch-canary");
    });
    setTauriInternals({ invoke });

    const opener = createExternalUrlOpener();
    await expect(opener.open(new URL("https://app.snaptrade.com/redeem?token=synthetic")))
      .resolves.toBe("unavailable");
  });
});
