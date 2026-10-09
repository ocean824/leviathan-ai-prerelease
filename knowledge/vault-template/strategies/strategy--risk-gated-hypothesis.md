---
schema_version: 1
note_id: 00000000-0000-4000-8000-000000000102
note_type: strategy
title: Risk-gated hypothesis record
status: draft
trust_label: project-source
created_at_utc_ns: 1783468800000000000
updated_at_utc_ns: 1783468800000000000
ingest: false
methodology: [hypothesis-review]
asset: [cross-asset]
regime: [unknown]
source_refs:
  - authority_class: project-prd
    locator: codespring-prd://self-learning-agent-council/backend-prd-self-learning-agent-council.md
    section: "Scope & behavior"
    sha256: 085fc92c14ec5a208b7a404798964f88ffca341f67282549f95165e59c4bd19a
  - authority_class: project-adr
    locator: project://repo/docs/adr/0004-sovereign-risk-isolation.md
    section: Decision
    sha256: 4d82555f22f62b0fb8e583294d1838d53b90f50b233bfe14d6c6432a66ee7880
---

# Risk-gated hypothesis record

Hypothesis: a research signal might be useful only within a specified market, data horizon,
and evaluation rule. This is a proposed test shape, not an algorithm or a claim of edge.

Falsifier: a time-ordered replay that fails its prespecified metric or reveals future-data
contamination rejects the proposal. The data window and exclusions must be fixed before
evaluation so a later result cannot redefine the question.

Risk boundary: even a successful research review does not authorize execution. A separate
sovereign risk decision is required for any intent. The present draft records no order route,
live permission, or achieved performance.
