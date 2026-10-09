export const archiveSecretCanaries = [
  "SYNTHETIC_ARCHIVE_API_TOKEN_01",
  "SYNTHETIC_ARCHIVE_PRIVATE_KEY_02",
  "SYNTHETIC_ARCHIVE_PROMPT_BODY_03",
] as const;

export const archiveSourceAsOf = "2026-10-06T12:00:00.000Z";

const replacement = {
  market_data_doc: "https://docs.example.invalid/market-data-pipeline",
  ea_builder_doc: "https://docs.example.invalid/ea-builder-knowledge",
};

export function archiveEntry(
  id = "archive-fixture-001",
  tags: readonly string[] = ["synthetic", "archive-fixture"],
) {
  return {
    id,
    source_type: "api",
    created_at_ns: "1791287998000000000",
    updated_at_ns: "1791287999000000000",
    tags,
    status: "archived",
    data: {
      note_body: "SYNTHETIC_PRIVATE_NOTE_BODY_MUST_NOT_RENDER",
      prompt: archiveSecretCanaries[2],
      credentials: {
        token: archiveSecretCanaries[0],
        private_key: archiveSecretCanaries[1],
      },
    },
  };
}

export function archiveListResponse(options: {
  sourceAsOf?: string;
  empty?: boolean;
  id?: string;
  ids?: readonly string[];
  tags?: readonly string[];
} = {}) {
  const ids = options.ids ?? [options.id ?? "archive-fixture-001"];
  return {
    ...(options.sourceAsOf === undefined ? {} : { as_of: options.sourceAsOf }),
    data: options.empty ? [] : ids.map((id) => archiveEntry(id, options.tags)),
    meta: { cursor: null, warnings: [], replacement },
  };
}

export function archiveDetailResponse(options: {
  sourceAsOf?: string;
  id?: string;
  tags?: readonly string[];
} = {}) {
  return {
    ...(options.sourceAsOf === undefined ? {} : { as_of: options.sourceAsOf }),
    data: archiveEntry(options.id, options.tags),
    meta: { replacement },
  };
}

export function archiveRunsResponse(options: {
  sourceAsOf?: string;
  empty?: boolean;
  id?: string;
  tags?: readonly string[];
} = {}) {
  return {
    ...(options.sourceAsOf === undefined ? {} : { as_of: options.sourceAsOf }),
    data: options.empty ? [] : [archiveEntry(options.id ?? "archive-run-fixture-001", options.tags)],
    meta: { cursor: null, warnings: [], replacement },
  };
}

export const forgedArchiveResponse = {
  data: [
    {
      ...archiveEntry("forged-content-must-not-render"),
      raw_payload: "SYNTHETIC_FORGED_RAW_PAYLOAD_MUST_NOT_RENDER",
      secret: archiveSecretCanaries[0],
    },
  ],
  meta: { cursor: null, warnings: [], replacement },
  forged: true,
};
