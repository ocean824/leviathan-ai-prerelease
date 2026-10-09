---
schema_version: 1
note_id: 00000000-0000-4000-8000-000000000103
note_type: market-structure
title: Source freshness in market observations
status: draft
trust_label: project-source
created_at_utc_ns: 1750000000000000000
updated_at_utc_ns: 1750000000000000000
ingest: false
methodology: [observation-review]
asset: [cross-asset]
regime: [unknown]
source_refs:
  - authority_class: project-prd
    locator: codespring-prd://self-learning-agent-council/backend-prd-self-learning-agent-council.md
    section: "Scope & behavior"
    sha256: 085fc92c14ec5a208b7a404798964f88ffca341f67282549f95165e59c4bd19a
---

# Source freshness in market observations

An observed mechanism needs an instrument, venue if relevant, timeframe, and source window.
The record should distinguish when an event occurred from when its evidence became available.
If a latency gap is found, pause the interpretation and preserve the gap as a source limit.

This note does not assert a current market condition. It illustrates how a draft can state
the boundary of its observations before any separate replay or decision process uses them.
