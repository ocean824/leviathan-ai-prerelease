# ADR-0005: Operator terminal is Vite + React + TS, not Next.js

**Date**: 2026-07-05 · **Status**: Accepted

## Context
Spec docs mention both "React/Next.js" and the BB-Terminal lineage
(Vite + React + TS + Lightweight Charts). The terminal is a local,
operator-facing workstation destined for desktop packaging (Phase 7) with
function-code workflows (CC/INTEL/QR/…) — not a public website.

## Decision
Vite + React + TypeScript. SSR/routing/edge features of Next.js add cost and
nothing of value to a local console; Vite matches the BB-Terminal code we may
absorb, keeps the desktop-packaging path (Tauri) simple, and builds in ~100ms.

Dev server on :3000 proxies `/api/*` → gateway :8000, so the terminal never
hardcodes backend origins.

## Consequences
- Lightweight Charts, command bar, and workspace tabs land directly in this
  shell in Phase 6.
- If a public marketing/admin web app is ever needed, it is a separate app —
  not this terminal.
