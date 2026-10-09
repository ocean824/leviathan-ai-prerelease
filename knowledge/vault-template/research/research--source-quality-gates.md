---
schema_version: 1
note_id: 00000000-0000-4000-8000-000000000101
note_type: research
title: Source quality gates for research notes
status: draft
trust_label: project-source
created_at_utc_ns: 1750000000000000000
updated_at_utc_ns: 1750000000000000000
ingest: false
methodology: [source-review]
asset: [cross-asset]
regime: [unknown]
source_refs:
  - authority_class: project-prd
    locator: codespring-prd://knowledge-ingestion-obsidian-sync/backend-prd-knowledge-ingestion-obsidian-sync.md
    section: "Backend PRD: Knowledge Ingestion (Obsidian Sync)"
    sha256: 0f5cab5f151bd91c81870cc8c0dd431fd9e20284f5bd766ba6942509f605e8f9
---

# Source quality gates for research notes

A document's label is only useful when its origin and revision are known. Before a research
observation is considered for ingestion, the operator should identify the source, its time
window, and which taxonomy values are supported by evidence. An empty taxonomy is a visible
draft condition, not a value to infer from prose.

The local note ID helps authors link drafts. The ingestion service assigns separate document,
version, and chunk identities after receiving a signed event from a registered watcher. This
example has not passed a tenant tag-policy review and remains excluded from ingestion.

Uncertainty: a file hash proves which source bytes were cited. It does not prove that a claim
in the note is correct, current, or suitable for a trading decision.
