export const REGISTRY = [
  { code: "CC", label: "Command Center", description: "Gateway, sovereign risk and journal overview", kind: "tab" },
  { code: "INTEL", label: "Market Intelligence", description: "Flow, positioning and market context", kind: "tab" },
  { code: "QR", label: "Quant Research", description: "Research workspace and model evidence", kind: "tab" },
  { code: "GP", label: "Global Positioning", description: "Cross-market positioning", kind: "tab" },
  { code: "HP", label: "Health & Performance", description: "System and strategy health", kind: "tab" },
  { code: "OMON", label: "Order Monitor", description: "Read-only order visibility; execution disabled", kind: "tab" },
  { code: "CURV", label: "Curves", description: "Rate and volatility curves", kind: "tab" },
  { code: "FXC", label: "FX Console", description: "Currency market context", kind: "tab" },
  { code: "WEI", label: "Wallet & Execution Intelligence", description: "Wallet and execution intelligence; controls disabled", kind: "tab" },
  { code: "JRNL", label: "Trade Journal", description: "Trade records and outcomes", kind: "tab" },
  { code: "RISK", label: "Sovereign Risk", description: "Risk status, halts and policy", kind: "tab" },
  { code: "GENOME", label: "Genome Registry", description: "Strategy genome inventory", kind: "tab" },
  { code: "LIVE", label: "Live Trading", description: "Paper, demo, live and MCP credential configurations", kind: "tab" },
  { code: "KNOW", label: "Knowledge Archive", description: "Read-only archived metadata; archived content is not displayed", kind: "tab" },
  { code: "LGD", label: "Live Guard", description: "LIVE remains disabled; operator switch and risk limits required", kind: "tab" },
  { code: "PACT", label: "Paper Activity", description: "Read-only OMS paper ledger activity", kind: "tab" },
  { code: "PAPR", label: "Paper Activation", description: "PAPER-only activation and revocation; LIVE remains disabled", kind: "tab" },
  { code: "EAC", label: "EA Template Catalog", description: "Read-only EA template catalog metadata", kind: "tab" },
  { code: "FLR", label: "Flash-loan Routes (read-only)", description: "Read-only flash-loan route view; LIVE remains disabled", kind: "tab" },
  { code: "DATA", label: "Data Sources", description: "Read-only market data source health and configuration", kind: "tab" },
  { code: "CHRT", label: "Charts", description: "Price, depth and footprint chart workspace", kind: "tab" },
  { code: "PORD", label: "Paper Order Ticket", description: "Paper order ticket; unavailable until an active scope can be verified", kind: "tab" },
  { code: "CONN", label: "Connections", description: "Provider connection status and credential entry", kind: "tab" },
  { code: "APPR", label: "Appearance", description: "Terminal theme and appearance preferences", kind: "tab" },
  { code: "CHAT", label: "Chat", description: "Assistant chat with governed tools and conversation history", kind: "tab" },
  { code: "PIPE", label: "Pipeline Replay", description: "Local replay and verdict", kind: "tab" },
  { code: "HELP", label: "Help", description: "Command and function directory", kind: "tab" },
  { code: "TODAY", label: "Today", description: "Operator daybook", kind: "view" },
  { code: "SYMBOL", label: "Symbol", description: "Single-symbol context", kind: "view" },
  { code: "STRATEGY", label: "Strategy", description: "Strategy context and controls", kind: "view" },
] as const;


export type NavigationCode = (typeof REGISTRY)[number]["code"];
export type RegistryEntry = (typeof REGISTRY)[number];
export const TAB_ENTRIES = REGISTRY.filter((entry) => entry.kind === "tab");
export const VIEW_ENTRIES = REGISTRY.filter((entry) => entry.kind === "view");

export function isNavigationCode(value: string): value is NavigationCode {
  return REGISTRY.some((entry) => entry.code === value);
}

export function resolveHash(hash: string): { code: NavigationCode; reason?: string } {
  let value: string;
  try {
    value = decodeURIComponent(hash.replace(/^#/, "")).trim().toUpperCase();
  } catch {
    return { code: "HELP", reason: "Invalid hash encoding. Showing command directory." };
  }
  if (!value) return { code: "CC" };
  if (isNavigationCode(value)) return { code: value };
  return { code: "HELP", reason: `Invalid hash #${value}. Showing command directory.` };
}
