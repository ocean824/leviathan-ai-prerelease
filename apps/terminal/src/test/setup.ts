import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

// Keep each acceptance case isolated from browser state and network spies.
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  window.history.replaceState({}, "", "/");
});
