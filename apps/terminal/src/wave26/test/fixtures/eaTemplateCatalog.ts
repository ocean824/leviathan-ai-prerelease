/** Synthetic EA catalog responses for independent terminal acceptance. */

export const EA_TEMPLATE_SOURCE_CANARY = "SYNTHETIC_EA_SOURCE_BODY_MUST_NOT_RENDER_7A31";
export const EA_TEMPLATE_GRAPH_CANARY = "SYNTHETIC_EA_GRAPH_BODY_MUST_NOT_RENDER_90C2";
export const EA_TEMPLATE_SECRET_CANARY = "synthetic-template-private-token-canary";

const templates = [
  { template_id: "MT4:bar_event", block_id: "bar_event", platform: "MT4" },
  { template_id: "MT4:compare.v1", block_id: "compare.v1", platform: "MT4" },
  { template_id: "MT4:crossover.v1", block_id: "crossover.v1", platform: "MT4" },
  { template_id: "MT4:entry_signal.v1", block_id: "entry_signal.v1", platform: "MT4" },
  { template_id: "MT4:exit_signal.v1", block_id: "exit_signal.v1", platform: "MT4" },
  { template_id: "MT4:sma_indicator", block_id: "sma_indicator", platform: "MT4" },
  { template_id: "MT5:bar_event", block_id: "bar_event", platform: "MT5" },
  { template_id: "MT5:compare.v1", block_id: "compare.v1", platform: "MT5" },
  { template_id: "MT5:crossover.v1", block_id: "crossover.v1", platform: "MT5" },
  { template_id: "MT5:entry_signal.v1", block_id: "entry_signal.v1", platform: "MT5" },
  { template_id: "MT5:exit_signal.v1", block_id: "exit_signal.v1", platform: "MT5" },
  { template_id: "MT5:sma_indicator", block_id: "sma_indicator", platform: "MT5" },
] as const;

export const eaTemplateCatalogResponse = {
  catalog_id: "leviathan_mql_source",
  version: 1,
  catalog_digest: "a".repeat(64),
  templates: templates.map((item, index) => index === 0
    ? {
        ...item,
        source: EA_TEMPLATE_SOURCE_CANARY,
        mql_source: EA_TEMPLATE_SOURCE_CANARY,
        graph_json: EA_TEMPLATE_GRAPH_CANARY,
        raw_payload: EA_TEMPLATE_SECRET_CANARY,
      }
    : item),
};

export const eaTemplateCatalogWithUnknownBlock = {
  ...eaTemplateCatalogResponse,
  templates: [
    ...eaTemplateCatalogResponse.templates,
    {
      template_id: "MT4:unsupported_block_v1",
      block_id: "unsupported_block_v1",
      platform: "MT4",
    },
  ],
};

export function catalogResponseWithTemplates(templates: readonly unknown[]) {
  return { ...eaTemplateCatalogResponse, templates };
}

export const invalidTemplateIds = [
  "mt4:bar_event",
  "MT3:bar_event",
  "MT4:bar event",
  `MT4:${EA_TEMPLATE_SECRET_CANARY}`,
  "MT5:bar_event/../source-canary",
] as const;

export function eaTemplateCatalogWithUntrustedTimestamp(field: "as_of" | "asOf") {
  return { ...eaTemplateCatalogResponse, [field]: Date.now() };
}
