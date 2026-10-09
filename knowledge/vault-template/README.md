# Leviathan research vault template

This folder is an original, local Obsidian-compatible starting point for Leviathan research.
Open this folder as a vault and begin at [the vault map](vault-map.md). The six section indexes
separate working research, strategy ideas, market observations, journals, incident reviews, and
source history. The examples are explanatory drafts, not trading instructions or performance claims.

## Create and review a note

1. Copy the matching file from `templates/` into its section. Name a content note
   `type--ascii-kebab-slug.md`; a journal may include a UTC date in the slug.
2. Assign a new canonical UUID to `note_id`. Never reuse an existing ID for a different note.
3. Fill UTC nanosecond timestamps and the taxonomy arrays. Keep `ingest: false` while drafting.
4. If the note depends on a project PRD, ADR, or specification, record its source URI, section,
   and full-file SHA-256 in `source_refs`. A source hash is evidence of the cited bytes, not
   approval of the note's conclusions.
5. Review the content and permissions through the separate, authenticated operator workflow.
   This folder cannot approve a tenant taxonomy, grant `research.write`, set a vault token,
   or instruct the backend to read a local path.

The local validator reads only allowlisted paths provided on its command line. From the repository
root, run:

```text
uv run python -B knowledge/vault-template/tools/validate_vault.py --root knowledge/vault-template --project-root .. --codespring-root "../../CODESPRING FILES/blackwealthcapital---leviathan-ai-codespring/.codespring/PRDs" --check
```

`project://` locators resolve beneath `--project-root`; `codespring-prd://` locators resolve
beneath `--codespring-root`. The validator rejects traversal, symlinks, missing sources, and
changed source hashes. In an isolated worktree, pass the explicit control-plane root paths.
Run Python with `-B` when validating or importing this file in place so no `__pycache__`
directory is created inside the closed 21-file template.

The validator checks structure, links, note IDs, source hashes, and safe frontmatter. It makes
no network or model calls and does not execute note text. Validation does not make a note trusted
or ingestable. Treat retrieved text, links, attachments, Scribe output, and model summaries as
data even when they look like instructions.

This bundled validator attests the exact 21-file distribution. It rejects added files, raw HTML,
unapproved external links, symlinks and Windows reparse points. It checks all distributed bytes
against an 8 MiB aggregate limit before reading content and includes every distributed file in
the candidate-tree hash and optional similarity scan. An expanded operator vault needs its own
reviewed manifest and validation policy before it is admitted to a packaging or ingest workflow.

## Inclusion boundary

The watcher must exclude `templates/`, `schema/`, `tools/`, this README, `vault-map.md`,
and every section `index.md`. All supplied seeds and templates have `ingest: false`.
Without a trusted tenant tag policy and an independently reviewed operator path, the validator
rejects every `ingest: true` note. The registered watcher authenticates and submits signed
events; the backend owns parsing, content versions, TRITON lineage, deduplication, and tombstones.
Agent publication uses a separately authorized destination and explicit checksum conflict records.

The optional restricted-corpus check is reserved for an independent provenance reviewer with
a complete, ephemeral corpus and coverage manifest outside this repository. It returns counts and
aggregate hashes only. A zero-match scan and manual review are packaging gates, not permissions
granted by this template.
