import { afterEach, describe, expect, it, vi } from "vitest";
import { createExternalUrlOpener } from "./externalUrlOpener";

describe("createExternalUrlOpener", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("invokes the native opener with the URL when running in Tauri", async () => {
    const invoke = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal("window", { __TAURI_INTERNALS__: { invoke } });

    const result = await createExternalUrlOpener().open(new URL("https://app.alpaca.markets/oauth"));

    expect(result).toBe("opened");
    expect(invoke).toHaveBeenCalledOnce();
    expect(invoke).toHaveBeenCalledWith("open_external_url", { url: "https://app.alpaca.markets/oauth" });
  });

  it("stays fail-closed in a plain browser", async () => {
    vi.stubGlobal("window", {});

    await expect(createExternalUrlOpener().open(new URL("https://app.alpaca.markets/oauth")))
      .resolves.toBe("unavailable");
  });

  it("maps native command failures to unavailable", async () => {
    const invoke = vi.fn().mockRejectedValue(new Error("URL_NOT_ALLOWED"));
    vi.stubGlobal("window", { __TAURI_INTERNALS__: { invoke } });

    await expect(createExternalUrlOpener().open(new URL("https://attacker.example/")))
      .resolves.toBe("unavailable");
  });
});
