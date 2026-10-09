---
schema_version: 1
note_id: 00000000-0000-4000-8000-000000000104
note_type: source-lineage
title: Revision chain for a knowledge source
status: draft
trust_label: project-source
created_at_utc_ns: 1750000000000000000
updated_at_utc_ns: 1750000000000000000
ingest: false
methodology: [lineage-review]
asset: [cross-asset]
regime: [unknown]
source_refs:
  - authority_class: project-prd
    locator: codespring-prd://knowledge-ingestion-obsidian-sync/backend-prd-knowledge-ingestion-obsidian-sync.md
    section: "Backend PRD: Knowledge Ingestion (Obsidian Sync)"
    sha256: 0f5cab5f151bd91c81870cc8c0dd431fd9e20284f5bd766ba6942509f605e8f9
---

# Revision chain for a knowledge source

An author can record a source URI and full-file hash in this note, then explain which revision
was read and what transformation or offset produced a claim. This authoring trail makes a
later review easier; it is not the backend's immutable lineage record.

The ingestion service owns trusted vault, document, version, parser, and chunk identities.
When a document changes or is deleted, that service records a new revision or tombstone.
No local note can replace that chain or grant permission to publish it.
