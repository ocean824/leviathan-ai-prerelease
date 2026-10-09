import type { ExternalUrlOpenerPort } from "../wave34/connections/model";

type TauriInternals = {
  invoke?: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
};

type TauriWindow = Window & {
  __TAURI_INTERNALS__?: TauriInternals;
};

/** Uses the desktop's host-pinned opener command; plain browser builds remain fail-closed. */
export function createExternalUrlOpener(): ExternalUrlOpenerPort {
  return {
    async open(url) {
      const invoke = (window as TauriWindow).__TAURI_INTERNALS__?.invoke;
      if (typeof invoke !== "function") return "unavailable";
      try {
        await invoke("open_external_url", { url: url.href });
        return "opened";
      } catch {
        return "unavailable";
      }
    },
  };
}
