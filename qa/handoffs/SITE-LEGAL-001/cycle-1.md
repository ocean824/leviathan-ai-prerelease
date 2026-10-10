---
kind: review
title: "SITE-LEGAL-001 cycle 1 implementation freeze"
comments: none
---

# SITE-LEGAL-001 cycle 1

Status: **frozen for coordinator integration review**. Diff inventory below compares lane-owned paths with the cycle-0 ledger; it excludes the unrelated pre-existing dirty baseline recorded in the start manifest.

## Provenance

- Canonical source: `XYRA-MASTER/projects/XYRASYSTEMS/LEVIATHAN AI/repo` (read-only)
- Worktree: `XYRA-MASTER/projects/XYRASYSTEMS/LEVIATHAN AI/worktrees/site-legal-001`
- Copied source commit: `d3208136d1872cf6e0bb33ec79aa06f01de98562`
- Start manifest SHA-256: `46c6415f33c764e2ec56da21f52fe743afdddf34c54f8b9fddf7469abbaca28a`
- Previous freeze: [cycle 0](cycle-0.md)
- Cycle-0 ledger SHA-256: `0e1b3dc67ab67a980479bf5a88497200523bbe82e45cd2ca83a83b4a26860cbd`

## Cycle-1 fixes

- Static Assets now receive extensionless page paths; `/site.css` is routable and the worker preserves static asset responses. Removed HSTS `preload`.
- Production build footer contains only the update note; the owner-review note appears only in incomplete draft builds. Removed internal plan, repository and publication language from public pages.
- Added the `-IncludeSite` opt-in. The facts gate, site build, site deploy and all page/CSS smoke checks run only when the switch is set; the three existing Workers remain independently deployable.
- Tightened JavaScript and PowerShell facts validation for placeholders, email, date, and custom domain. Added required owner facts for deletion retention, legal retention and refund policy. Set container host to `Cloudflare (Workers and Containers)`; legal name remains owner-confirm pending.
- Updated privacy, terms, deletion, security and subprocessor text for actual account, Stripe, data-gateway, update-check, AI-provider and desktop/web credential flows. Added Google Limited Use wording and the privacy-to-deletion link. Deletion is described as operator-run and append-only audit records are disclosed.
- `/app` remains a placeholder. No application was built and nothing was deployed.

## Verification

- Real workerd acceptance suite: **137 passed, 0 failed**. It exercised Static Assets, all 10 pages and titles, `/site.css`, unknown routes, redirect behavior, headers, content, facts gate and claims against the canonical code.
- Vitest: **29 passed**; link checker: **passed** for 10 built pages.
- Pester: **5 passed**; PowerShell parser check: **passed**.
- Deploy `-WhatIf` output checked with and without `-IncludeSite`; site inclusion is false by default and clearly shown when opted in.
- Mutation suite: **16 run, 16 killed, 0 survived**.
- No secrets used; no Worker deployed.

## Owner facts still missing

- Owner confirmation of legal name `Lossless Holdings, LLC`.
- State or country of formation, business mailing address, and public support email.
- Owner-supplied full regulatory-status sentence.
- Approved custom public domain and effective date.
- Owner-confirmed account deletion period in days and maximum legal retention period in years.
- Owner-confirmed refund policy.

The web API container host is set to the owner-provided conditional-GO value. The company facts gate remains closed until all required facts are supplied and confirmed.

## Diff inventory

| Path | Delta | Cycle-0 SHA-256 | Cycle-1 SHA-256 |
|---|---|---|---|
| `infra/release/cloudflare/Deploy-LeviathanWorkers.ps1` | modified since cycle 0 | `e3222228075cf9c93164e9db56d81f2fcbca15701d1288b89fe0bc2edbdd9302` | `3d5848745fb628553b3bcc9dd81ee649b46f17f70df1dcf24b93cab721e8fef1` |
| `infra/release/tests/SiteFacts.Tests.ps1` | modified since cycle 0 | `ea962f97e01e8394b1480b4380187e4c83576549446d8d39d9885bec6fbb99a9` | `137819c3891cddf4212daae6748087b4aa5b991c54da91942faf12e28f96818f` |
| `qa/acceptance/SITE-LEGAL-001/README.md` | reviewer harness included/adapted | `-` | `6654c4b6b41b7b0581dcf6d2650056daf3778bffc49752eaac8a65f168d08ed2` |
| `qa/acceptance/SITE-LEGAL-001/acceptance.test.mjs` | reviewer harness included/adapted | `-` | `708825e027ba563ce0f52e221f7426f3f8333f599fb13c2a75ce8b337294dac3` |
| `qa/acceptance/SITE-LEGAL-001/helpers.mjs` | reviewer harness included/adapted | `-` | `80f744c748b59cdb070a250eaea59783fd026d21c6fff1555ecb9b11499abe50` |
| `qa/acceptance/SITE-LEGAL-001/mutants.mjs` | reviewer harness included/adapted | `-` | `a9969634f3c9150b963ca781fad2a111b1bc55eb0fe931cb834d8fc4f1ed3460` |
| `workers/site/pages/app.html` | modified since cycle 0 | `acf8ae3dc1434ec2af1ffff42be4979ec945153387480fe5dd280b429179be1b` | `8d6c14df7221d32332a2e70c8f47071a373b9731ec81c47fc87d15321af57e15` |
| `workers/site/pages/data-deletion.html` | modified since cycle 0 | `28c52d2c93d2d4d7407e794b28fc716a7b48037284bd2059d82e53c4a883fc30` | `6b5b0e7f1160e1e266ea3126b2d3dfaf033a12723bae781ed458ab0f19f3a5e8` |
| `workers/site/pages/home.html` | modified since cycle 0 | `55a3801e32966efccc69305d3ea90e3dca5a863130834205bd57ed67f0aeaeef` | `76a33fb7fdb0238066ea84c884e78346999596bcc1232540547b36311d2ffc1e` |
| `workers/site/pages/privacy.html` | modified since cycle 0 | `ef5c2042dc3123cb7bcb436584d63c058d5e80ec599fca1bac0446afa14216c1` | `f85a8eb1f27f1c06c84e23a8fcd76fcee47a25fb78b6af7452c53d914dca14f2` |
| `workers/site/pages/security.html` | modified since cycle 0 | `595790d0f3d874ccbc742e7f7f162e5c06f78711dc6b920b27bcd15f0126eafe` | `6bd462bf0c608a355aa99888195c5f1104334f1c3d02b280fd464c6b9f63311a` |
| `workers/site/pages/subprocessors.html` | modified since cycle 0 | `898cd9bc1e02be7e4c8706d1bd113410c249f2063b277aa25feeb105ebc9e36e` | `f5c79669e7927e024d26b501bd86f287d8f6430ba405004227a8c89cb3d29da3` |
| `workers/site/pages/terms.html` | modified since cycle 0 | `8c681b54f2fc13776109a4a2982aadf9cc3c4fb9a2fe6eed10f7c7b86ced4235` | `64790e6e99b6a71957fa73150cd12d0b8106cb2539a557895efbc26a4e921f79` |
| `workers/site/scripts/build.mjs` | modified since cycle 0 | `f4c587662c68a4cdef688d7bbebd5b0d5d087e6d5ae84d86f505fdf9162d3b93` | `3e295d2f604baf258fdcd96db3672451bd69569bfd1a94543eae76fc0f10c996` |
| `workers/site/site.config.json` | modified since cycle 0 | `77b4d30609582cb64fa08eb6a5900daaab488af73881e0510dd1255519d4e357` | `f3e813a11b16fc91967e23d0ea8139ae0244aa780d77246d06cb67be5029866e` |
| `workers/site/src/facts.mjs` | modified since cycle 0 | `1c8c5eecb172e5ecb24ddb904396bf123f3c70c1e1fab0064ce47435df780d6f` | `872bf30f095972b95e3825b1d28ef897ce5b0cef71bb41a7d316c257d1097ff3` |
| `workers/site/src/index.ts` | modified since cycle 0 | `0900a4f6ab0ea6dfd546e19cda63ccfce6d49f0350344a51d20cffeb13b05e5e` | `44e685d7d2854257a7b369838c2488e9e184ee2d58ee4faa91530d068ce4c950` |
| `workers/site/src/site-facts.psm1` | modified since cycle 0 | `0a806a0e98b37ba4016883bde0fa0dafa0c7de42a716ce0d03f5be0adb1cc3db` | `c22e66be8d244d1507119af42ea6198928fbdb85d30647c2c1df80d2368a4995` |
| `workers/site/tests/site.test.ts` | modified since cycle 0 | `304ca0ca8b1c5fa833fe66da0bcaef2b77e89087746350d10465d42114735503` | `c81ee50f17b0562e655b322501563e386b169e339968b37ccfa6f978b8257895` |


## Integration boundary

This freeze records implementation and verification only. Legal content remains gated until owner facts are complete; the coordinator handles deployment after integration review.
