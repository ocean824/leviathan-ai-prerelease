# SITE-LEGAL-001 - Cycle 2 freeze ledger

## Parent and scope

- Parent: cycle 1 snapshot at `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\worktrees\site-legal-001`; source ledger SHA-256 `fa7922a777b79792adfac20cd7beb6465d4e06224a1fa444efd011a33642f461`.
- Start manifest: [`cycle-2-start-manifest.json`](cycle-2-start-manifest.json), source tree SHA-256 `cc9691489b1f7921090e0f07d2090cf9eb0a60e6abe14c8bfe39ceb8d76d237a` across 3079 files.
- This is a cycle-1-derived snapshot freeze. The integrated canonical comparison and hash are intentionally pending the owner's integration confirmation.
- Independent review and acceptance files were not edited. No deployment or secrets were used.

## Cycle 2 changes

| Path | Cycle 1 SHA-256 | Cycle 2 SHA-256 |
|---|---|---|
| `infra/release/tests/SiteFacts.Tests.ps1` | `137819c3891cddf4212daae6748087b4aa5b991c54da91942faf12e28f96818f` | `a35dc6c94016aad2cd67561fbdb73d9b2e605bb42d75b3bcb35df1abe81059e6` |
| `workers/site/pages/app.html` | `8d6c14df7221d32332a2e70c8f47071a373b9731ec81c47fc87d15321af57e15` | `27466b7f515aaf98c5bfe8ec73e605c5391fe627b52f1a282bcdcf47cc107656` |
| `workers/site/pages/data-deletion.html` | `6b5b0e7f1160e1e266ea3126b2d3dfaf033a12723bae781ed458ab0f19f3a5e8` | `d093322af950c48313d45f813e91116c8ffa66a28a5c7e29849c601b11302636` |
| `workers/site/pages/home.html` | `76a33fb7fdb0238066ea84c884e78346999596bcc1232540547b36311d2ffc1e` | `bca918372a1db063879416a10772b2ac30f4d30b1d9a1ab512eb75261a16f51e` |
| `workers/site/pages/privacy.html` | `f85a8eb1f27f1c06c84e23a8fcd76fcee47a25fb78b6af7452c53d914dca14f2` | `057539bc5c273c153e69c62313069bd64339f6599e3c35eed94a037d792516bb` |
| `workers/site/pages/terms.html` | `64790e6e99b6a71957fa73150cd12d0b8106cb2539a557895efbc26a4e921f79` | `79158093278a45250f86d25c020ddf37587cb0249e5330aa24d3d351a0f0ca03` |
| `workers/site/scripts/build.mjs` | `3e295d2f604baf258fdcd96db3672451bd69569bfd1a94543eae76fc0f10c996` | `e59926bd795542636b04c403aa0c76263b83670c43d59e1a009f9489e8b39266` |
| `workers/site/site.config.json` | `f3e813a11b16fc91967e23d0ea8139ae0244aa780d77246d06cb67be5029866e` | `a4fad6f5b5e4a7d5efdc2f79050412a091d9b20b4bcca9beffed7166fccca949` |
| `workers/site/src/facts.mjs` | `872bf30f095972b95e3825b1d28ef897ce5b0cef71bb41a7d316c257d1097ff3` | `df1e997047ebba32ce6f01f80eae18a7e3566795126a2cf1a00946cd396eaadb` |
| `workers/site/src/site-facts.psm1` | `c22e66be8d244d1507119af42ea6198928fbdb85d30647c2c1df80d2368a4995` | `e7c1c7200a6c353c00789e4d708e78200fe5257c21b364d6095edd4149a850d7` |
| `workers/site/tests/site.test.ts` | `c81ee50f17b0562e655b322501563e386b169e339968b37ccfa6f978b8257895` | `4e8672ff5b8454ef1f9d388bb271a5aa437a38d080424f1d7e64afb1ab0859bb` |
| `workers/site/tests/build-config.test.ts` (added) | - | `19af9d60bd2cf16290f2a9595536490b8c78948d8ba646ef7af26ae8f505d000` |

## Requested polish

- Added required `billing.cancellation_method` fact with allowed values `email` and `portal`; config defaults to `email`. Terms render the interim account-email cancellation wording or the Stripe billing portal wording based on that fact.
- Added matching JS and PowerShell validation for cancellation method; support email rejects `mailto:`; retention days must match `[1-9][0-9]{0,2}` and legal-retention years `[1-9][0-9]?`.
- Removed the extra homepage period, used plain retention wording, clarified desktop versus web AI prompt routing, and applied the requested app, deletion-page, and bold-label copy polish.
- Facts still missing: owner confirmation of `Lossless Holdings, LLC`; formation state/country; mailing address; support email; full owner-supplied regulatory sentence; approved custom domain; effective date; account-deletion period; maximum legal-retention period; refund policy.
- Container host remains `Cloudflare (Workers and Containers)`; product remains `Leviathan AI`.

## Verification

- `npm test`: passed, 35/35 Vitest tests.
- `npm run check:links`: passed for 10 generated pages.
- `Invoke-Pester -Path infra/release/tests/SiteFacts.Tests.ps1`: passed, 7/7.
- Strict `npm run build`: failed as expected with `SITE_FACTS_INCOMPLETE` for missing owner facts.
- Cycle-1 real-workerd acceptance was previously reported as passing; cycle 2 did not modify routing. The independent `acceptance-c1.test.mjs` still asserts portal cancellation and needs its owner to align it with this cycle's default-email decision.

## Hash boundary

No hash against the integrated canonical repository is recorded in this ledger. Generate that comparison only after the coordinator confirms cycle-1 integration.
