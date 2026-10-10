# API-ANYTHING-001 Cycle 4 freeze ledger

- Generated at: `2026-10-10T05:50:26+00:00`
- Baseline: C4 start manifest (1758 files; SHA-256 `503c2b4d433404e6ca047d70d839386af2949accdc95d06e75337625a71833c4`)
- Source Cycle 3 ledger SHA-256: `c79fa744c2e22a45e5a941d4890abfcf93af64c40339a9cf8c4adfbb19ec3ae1`
- Diff totals: 9 added, 12 modified, 1 deleted.
- Excluded generated/cache directories: `.git`, `.venv`, `node_modules`, `target`, `dist`, Python caches, `.scratch`, and `.vendor-build`.
- Excluded the three shared `public_sources` files owned by PUBLIC-DATA-001, integration backups, and independent `qa/acceptance/API-ANYTHING-001/cycle2/` files.

## Cycle 4 changes

- The learn canary merges structured 403/429/503 wall signals into the vendor result, resets the signal per request, and routes a recorded 403 wall through the built vendor and hand-off logic. The production stdio test exercises learn dispatch in replay-only mode.
- Added per-operation native-to-contract response recipes, passed them to `addOperation`, and recorded the recipe digest, fixture origin, and review note in candidate and pin metadata. Realistic native bodies for all five operations pass the built extractor and strict schemas.
- HTML fixture sanitization removes scripts, forms, hidden fields, credentials, and patterned personal values; tests cover Fed and Senate-style pages. JSON redaction is value/pattern based.
- First-seen is write-once per source key plus content hash. A persisted monotonic floor prevents clock rollback from moving new stamps backward. Three-fetch regression coverage passes.
- Raw fixture replay stores temporary homes under app data and bypasses network pacing. The real-vendor test verifies replay completes under one second at a five-second cadence.
- Removed the dead `headlessUserAgent()` / `probeHeadlessUA()` implementation from the vendor patch and built runtime. Removed the stray worktree `artifacts/` copy and verified it is absent.
- Live learning remains paused; no operation is pinned or activated. Candidates require writer, acceptance, review, and coordinator integration before a committed pin can serve.

## Verification

| Gate | Result | Scope |
|---|---:|---|
| `npm test` | 21 passed | Sidecar unit tests and production stdio end-to-end tests |
| Market-data pytest | 1,150 passed | Explicit C4 package source path; all tests |
| Coordinator finding acceptance | 9 passed, 210 deselected, 3 xfailed, 1 xpassed | `-k finding`; independent cycle2 directory excluded |
| Cycle 1 production-policy acceptance | 60 passed | `qa/acceptance/API-ANYTHING-001/cycle1` |
| Ruff | scoped pass; 67 legacy F811 findings in whole-tree run | Excluded integration backups and acceptance cycle1/cycle2; changed harnesses and ledger script pass independently |
| mypy | passed | Default (442 files), Linux, and Darwin client-platform runs |
| Broad legacy acceptance collection | 116 failed, 103 passed, 3 xfailed, 1 xpassed | Not a C4 gate: it expects old unpinned status and client envelopes, and its ledger test hard-codes the previous freeze; independent cycle2 remains excluded |

All C4 changes are included before hashing this ledger. No live learning was performed. The sidecar does not serve any operation until a reviewed, hash-pinned registry entry is integrated. The independent cycle2 acceptance directory was not modified or included in the ledger; its owner-maintained tests are separate from this lane.

## Diff-generated file inventory

| Status | Path | Old SHA-256 | New SHA-256 | New bytes |
|---|---|---|---|---:|
| deleted | `artifacts/leviathan-build/market-data-buildout/api-anything-001/index.md` | `2277ba02d01bd63bad846d49c33b411f9b065ad22a0a1355f2c37ac7da52c4cc` | `-` | - |
| modified | `qa/acceptance/API-ANYTHING-001/aa_harness.py` | `a9d5b9afe8d6e45117ff0be48344b6afc4028aca1a8e9b9ca63ef1bf104d2e45` | `00c36d23734b4ba55fceb13f49941378e1e9b0219f410ca1b254a34c00330938` | 20162 |
| modified | `qa/acceptance/API-ANYTHING-001/cycle1/c1_harness.py` | `184e70cf2d84b1a069a54a9e9bf09c0e7946e41b37646a821e316b02971388ea` | `002ecc3d08763f3e3074e4d803281a83d47a21e6c0069c211a5a12013af32de6` | 20577 |
| added | `qa/handoffs/API-ANYTHING-001/cycle-4-start.json` | `-` | `503c2b4d433404e6ca047d70d839386af2949accdc95d06e75337625a71833c4` | 350965 |
| added | `qa/handoffs/API-ANYTHING-001/generate_cycle4_ledger.py` | `-` | `1d26550e49946ccc43aeef525c494c94b271a56c7901039bcb493c954f1b815e` | 7322 |
| modified | `services/public-collector/README.md` | `5096c586b651a120719e40bad6c81715508f81a3892e19d2f9073d830cd5b09b` | `06ad5308a89dcdf7d9b9e5bba768e7a8cada29f1bf04461ca606b9c4167a86aa` | 5976 |
| added | `services/public-collector/fixtures/challenges/cf-challenge-403.html` | `-` | `f7e0fee5d7c8158b6f2137825924e500d936b27c449012dfde028b19dd0da60a` | 211 |
| modified | `services/public-collector/patches/api-anything-runtime.patch` | `e56ba7dc7a032392b58568fb5f172ef1cb2856e83c1a22b0b32870585dd4a929` | `36135f286cb13b7c4e65de049ccc0beaa56f47aad6042a84d60ecf4edfbdad67` | 96695 |
| modified | `services/public-collector/runtime-manifest.json` | `abab6418f42ccb477ef266b623e2589d8b06987c4211881e4d101180e3828a18` | `27e714928715ad10a790299855175682a9b3897619603eff3917c82f67f3115f` | 459 |
| modified | `services/public-collector/scripts/build-vendor.mjs` | `36dcf3d8e158cd1ee2e685beec2db0d3b11c3bd7ebe3b540dea71594945a42cf` | `504b0c2bd7a754722fc5d82adf9aa83b54ec6fea6df88260bbee003f6f3ac836` | 4072 |
| added | `services/public-collector/src/challenge-signal.ts` | `-` | `619cc8459813283caeb11eef8dd27316fcd7b59d3811c3c17c6570afce639c01` | 775 |
| modified | `services/public-collector/src/contracts.ts` | `49079e92f168092d29211ea6334a8d9b92501f8518b63718f28222e8e7f871ca` | `a64e49a60b56a5529d62ecb890458496923ffad616d175de38289bc7d2059d3b` | 8988 |
| added | `services/public-collector/src/first-seen.test.ts` | `-` | `ffde8e68586c23f85b001cb0c170edea498f240fa4071efa065bda2283e7036b` | 1359 |
| added | `services/public-collector/src/first-seen.ts` | `-` | `dd0fe14a8fda666d846505a022b3099f6f04ddbf832a1edb7051b9a0378a6b38` | 2505 |
| modified | `services/public-collector/src/fixture-replay.ts` | `1af06dcac56598fa54d2ec49c7b0a1902374091b27964e85374b9afda7ddc7c3` | `31dfe94c45818389aec2fd81b66387768b4b524183999ef8b6936557aed61b47` | 1611 |
| added | `services/public-collector/src/fixture-sanitize.test.ts` | `-` | `675f140781cd2a1fce4a01936025e71260a99bf5ad0db92d0dbcb4a902e6fa3b` | 1425 |
| added | `services/public-collector/src/fixture-sanitize.ts` | `-` | `9393ba3900501a0b746a8d4344b774f123f7c932aca6e53468bdeb0490e9e8bc` | 2473 |
| modified | `services/public-collector/src/learn-canary.test.ts` | `2453115a2648aa427ed6cb614e588c8ddbdc207f5d2b0911ad7663475fe0cdb1` | `a9f21d4095109edbe5853dfcb25a16cc875a79e7b022f6428d4a78f665fc8e49` | 9757 |
| modified | `services/public-collector/src/main.test.ts` | `abbef6331a4f2f99becad937ec0854111a1d6ea51915f45114b3f1e3fab200f3` | `0cbec59d7f69e916c63d4fe1e49465ce8072fada97db0113865ff8fd74dde0be` | 3654 |
| modified | `services/public-collector/src/main.ts` | `a8a4a0f1225a85c8a39f3c211e2e12a85fbd6eb51006319d200d638dce801d64` | `5fb3ccc9cf1dd017f1ea9d63ff6d276c648df844c0a1b3dbe6719c5cc7386893` | 45189 |
| added | `services/public-collector/src/mapping.test.ts` | `-` | `7f83737c587faaf2954cfc7f7ddc2b99d04887bf68820397d05463d6411a2e38` | 1997 |
| modified | `services/public-collector/vendor/api-anything/src/browser.ts` | `a99622a66ffc0faae89652cec18468f50e6299d5a96cead2a4d52a222152d1bc` | `30e937bee3a0dc0bb3544222b0e2b53de8b53d6bb930d624341e54a12f2aec3c` | 50917 |
