import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

type Mode = "call" | "learn" | "repair";
type RateOperation = {
  last_send_at?: string;
  last_success_at?: string;
  backoff_until?: string;
  last_learn_at?: string;
  last_repair_at?: string;
};
type RateState = { operations: Record<string, RateOperation> };

export class PersistentRateLimiter {
  constructor(private readonly path: string) {}

  private async read(): Promise<RateState> {
    try {
      const parsed: unknown = JSON.parse(await readFile(this.path, "utf8"));
      if (!parsed || typeof parsed !== "object" || !("operations" in parsed) || !parsed.operations || typeof parsed.operations !== "object") throw new Error();
      return parsed as RateState;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { operations: {} };
      throw new Error("RATE_STATE_INVALID");
    }
  }

  private async write(state: RateState): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const temporary = `${this.path}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(temporary, JSON.stringify(state), { mode: 0o600 });
    await rename(temporary, this.path);
  }

  async gate(id: string, mode: Mode, cadenceMs: number, minIntervalMs: number): Promise<void> {
    const state = await this.read();
    const operation = state.operations[id] ?? {};
    const now = Date.now();
    const backoff = operation.backoff_until ? Date.parse(operation.backoff_until) : 0;
    if (!Number.isFinite(backoff)) throw new Error("RATE_STATE_INVALID");
    if (now < backoff) throw new Error("RATE_LIMITED");
    const lastSend = operation.last_send_at ? Date.parse(operation.last_send_at) : 0;
    if (!Number.isFinite(lastSend)) throw new Error("RATE_STATE_INVALID");
    if (now < lastSend + minIntervalMs) throw new Error("RATE_LIMITED");
    if (mode === "call") {
      const lastSuccess = operation.last_success_at ? Date.parse(operation.last_success_at) : 0;
      if (!Number.isFinite(lastSuccess)) throw new Error("RATE_STATE_INVALID");
      if (now < lastSuccess + cadenceMs) throw new Error("NOT_DUE");
    } else {
      const key = mode === "learn" ? "last_learn_at" : "last_repair_at";
      const last = operation[key] ? Date.parse(operation[key]!) : 0;
      if (!Number.isFinite(last)) throw new Error("RATE_STATE_INVALID");
      if (now < last + minIntervalMs) throw new Error("RATE_LIMITED");
      operation[key] = new Date(now).toISOString();
    }
    operation.last_send_at = new Date(now).toISOString();
    state.operations[id] = operation;
    await this.write(state);
  }

  async success(id: string): Promise<void> {
    const state = await this.read();
    const operation = state.operations[id] ?? {};
    operation.last_success_at = new Date().toISOString();
    delete operation.backoff_until;
    state.operations[id] = operation;
    await this.write(state);
  }

  async backoff(id: string, delayMs: number): Promise<void> {
    const state = await this.read();
    const operation = state.operations[id] ?? {};
    operation.backoff_until = new Date(Date.now() + Math.max(1_000, delayMs)).toISOString();
    state.operations[id] = operation;
    await this.write(state);
  }
}
