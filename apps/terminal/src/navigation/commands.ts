import { isNavigationCode } from "./registry";
import type { NavigationCode } from "./registry";

export type FilterKey = "symbol" | "venue" | "strategy" | "timeframe";
export type ParsedCommand =
  | { type: "navigate"; code: NavigationCode }
  | { type: "symbol"; symbol: string }
  | { type: "filter"; key: FilterKey; value: string }
  | { type: "disabled"; reason: string }
  | { type: "error"; message: string };

const SYMBOL = /^[A-Z0-9.-]{1,20}$/;
const FILTER_VALUE = /^[A-Z0-9._-]{1,40}$/;
const FILTER_KEYS = new Set<FilterKey>(["symbol", "venue", "strategy", "timeframe"]);

export function parseCommand(input: string): ParsedCommand {
  const text = input.trim();
  if (!text) return { type: "error", message: "Enter a function code or command." };
  const bare = text.toUpperCase();
  if (isNavigationCode(bare)) return { type: "navigate", code: bare };
  if (!text.startsWith("/")) return { type: "error", message: `Unknown function code: ${text}. Type HELP for directory.` };

  const [verb, ...args] = text.split(/\s+/);
  const argument = args.join(" ").trim();
  switch (verb.toLowerCase()) {
    case "/help":
      return argument ? { type: "error", message: "/help takes no argument." } : { type: "navigate", code: "HELP" };
    case "/tab": {
      const code = argument.toUpperCase();
      return isNavigationCode(code)
        ? { type: "navigate", code }
        : { type: "error", message: argument ? `Unknown function code: ${argument}.` : "Usage: /tab <code>." };
    }
    case "/sym": {
      const symbol = argument.toUpperCase();
      return SYMBOL.test(symbol)
        ? { type: "symbol", symbol }
        : { type: "error", message: "Usage: /sym <ticker> (1–20 letters, digits, . or -)." };
    }
    case "/filter": {
      const match = /^([a-z]+)=([^\s=]+)$/i.exec(argument);
      if (!match) return { type: "error", message: "Usage: /filter <symbol|venue|strategy|timeframe>=<value>." };
      const key = match[1].toLowerCase() as FilterKey;
      const value = match[2].toUpperCase();
      if (!FILTER_KEYS.has(key)) return { type: "error", message: `Unsupported filter: ${match[1]}.` };
      if (!(key === "symbol" ? SYMBOL : FILTER_VALUE).test(value)) return { type: "error", message: `Invalid ${key} filter value.` };
      return { type: "filter", key, value };
    }
    case "/omega":
      return { type: "disabled", reason: "ØMEGA bridge unavailable" };
    default:
      return { type: "error", message: `Unknown command: ${verb}. Type HELP for directory.` };
  }
}
