# ADR-0002: Retire ORACLE naming; the package is `leviathan_core`

**Date**: 2026-07-05 · **Status**: Accepted

## Context
The spec repo evolved from an earlier system called ORACLE; several docs still
use `src/oracle/` paths and "ORACLE must…" language. The product, org branding,
and CodeSpring project are all LEVIATHAN AI.

## Decision
All code namespaces use `leviathan_*`. ORACLE survives only in doc citations.
The module layout otherwise follows the spec's implementation-module-map
(schemas, ingress, state, truth, decision, risk, execution, journal,
research, knowledge, integration).

## Consequences
- No dual naming to confuse contributors or grep.
- Doc digests note the mapping once; no code-level aliases.
