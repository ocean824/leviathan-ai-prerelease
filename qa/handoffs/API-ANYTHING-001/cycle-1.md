---
kind: spec
title: "API-ANYTHING-001 cycle 1 freeze ledger"
---

# Cycle 1 diff-generated freeze ledger

- Generated at: `2026-10-10T03:20:41+00:00`
- Baseline: `qa/handoffs/API-ANYTHING-001/cycle-1-start.json` (1711 source-tree files) copied from the frozen Cycle 0 tree.
- Cycle 0 source ledger SHA-256: `803d3b88dcc3734fd01c8b65695fa567966822aff7fb91d7fe8e00ac770fcb13`.
- Diff counts: **19 modified, 22 added, 0 removed** after the exclusions below.
- The `cycle-1.md` ledger excludes itself from its own file table.

## Diff

| State | Path | Before SHA-256 | After SHA-256 | Bytes after |
|---|---|---|---|---:|
| modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_client.py` | `cd4ce506bd5a1f02378c9888bd9f15682c7a5816e8a5e3ceb77ce9bc121b2aad` | `92d8c6ac5bcd59773e78ee5088de4d3160d8ce116339d63d4eb0bf3918560afc` | 37890 |
| modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_registry.py` | `836398f56809a5da6f56aac70ec6f3dc35721ef1dbaa499a97a8d418e698a2f5` | `daf47d82aefee2cbb12678d2bde13c8771397256510d1de3327892904dd87ebd` | 5062 |
| modified | `packages/leviathan-market-data/tests/fixtures/api_anything_fear_greed.json` | `5eebcc77b9e23440ff65dbf434edfbdc857e17c0de436661c164e90f583bf30c` | `c523606a01b59c7bbdbf509801af3cdaf9e68c9498d345f1ffc69bc35b8d32bc` | 1088 |
| modified | `packages/leviathan-market-data/tests/test_api_anything_client.py` | `202a42dd3da47e9019f4c1b1a55cc2c4554fa38cca3e8699c51575eef8a59220` | `6b76aedd16b89812af1380d2b619650780320b56faa69b22b171732134121cc3` | 12049 |
| modified | `pyproject.toml` | `26f2c0abc7a22a21e6214096e75be69c876d0b3ed8171c9370c5f2f3a1474251` | `90fada55ceb5d5cc60678aca9df5e7e4da4361ff2ac135af3ef600c766b20ca1` | 2152 |
| modified | `services/public-collector/README.md` | `5c50496da6c1b60b87383447cac8d83ba3384e63a1495b2e8a92d391889c3bfd` | `9367c90cca2a8f715266f62ff0519e9b69369be620fd57944bdc0a185f0de631` | 5083 |
| modified | `services/public-collector/package-lock.json` | `2d0ab6d6367017045d4a986b565d43dbcaf6de2319741cd1168c1492dd740675` | `7463c4c3f2a909d2c28059c6341c188b2eec5b89a160342e4c8cd74b94f32290` | 36656 |
| modified | `services/public-collector/package.json` | `16950ca2a433b943e778c280ac60f23dd06169147e3dc3a8a4b56854230ad4e9` | `b123c421380fd0cb421154f0569e44ab4bcf251a18cad470b27526bfe36fdbb5` | 539 |
| modified | `services/public-collector/src/challenge.ts` | `47dfd358fa1c58cf6a9982ad3dc4f35d5ea9ea7d5ba154c4c655f1d0d003e414` | `1a66b7621226b436f2c604adc700383217c85a37b799eab58e0761b4ea5dcaba` | 4876 |
| modified | `services/public-collector/src/collector.test.ts` | `a3412d63cb1bf1714b13111b29c25968fb969cdab52ef41ab2a5459c4e0a9626` | `485351d74049516b81010bf1267e9cc51f07f2ba691a810547fcc819772357a5` | 4225 |
| modified | `services/public-collector/src/contracts.ts` | `e2ba04ff6418a06284f341057163bbc3dff0e972fd61985d401d93467611ffed` | `a29e4c3c7e52862ed8a618cf9bfaa44aad30a405fda14709a6e3d465864c1d18` | 7561 |
| modified | `services/public-collector/src/main.ts` | `3acb6049fe541e73ed0c5b1a5416e5831eff82bfae1d1f63076fa0d57e3a5023` | `0259f2ac0994994ab78b7b4deabc7673d8fbc2a069339bf66c28a856af03fb98` | 37090 |
| modified | `services/public-collector/vendor/api-anything/package-lock.json` | `b553bd92662f3ee558fe44b03744b854f1bf85e5d2cf4b0aa65d6dfd7ae5c1dd` | `337136004342df28cf2961e4654662c0c5e52423c4319235563771c761ea160b` | 7112 |
| modified | `services/public-collector/vendor/api-anything/package.json` | `d4fc3de4fac6a635ae52b8337a72432ff8c5ad9b885805d92730a6e7568500ab` | `5349af07d72cd721a15a99285a680bc7053db1fed12c6006aac43b97df37b339` | 931 |
| modified | `services/public-collector/vendor/api-anything/src/browser.ts` | `01402b94285b04fb8405f7261305070bb093dbfbecd25108e21777adeb3ac3de` | `3fdb28de2435a9abeaed390ed04937cdbe1887e6476b9cebd0aca7517c9f3d0f` | 52734 |
| modified | `services/public-collector/vendor/api-anything/src/classify.ts` | `bf3df3297f605063d152f23053593def5a4a654fdc2b85978daddca97d6c4276` | `8a2038e3f52ad4b226dceb1ad9278165fbbd2d8fbce8909dec8823dd2f9ce02b` | 20899 |
| modified | `services/public-collector/vendor/api-anything/src/execute.ts` | `c99fc764687a8820089bee166801b437ca9af40870bb7c13d3cb66e050908749` | `faa7f4ac2baf7aefeac82438633871ffa31f0f7b186baa8a2507a4f6f90d3c83` | 27291 |
| modified | `services/public-collector/vendor/api-anything/src/heal.ts` | `322681bf8ff0661a256b13b5f4f4513cdbd691a9a84cf8df6a83d948f397884a` | `97b73b9877a2d8becee26674975cdd3a43131166eb90b52b5685ac0fe6d82a22` | 52260 |
| modified | `services/public-collector/vendor/api-anything/tsconfig.build.json` | `a9ed88d802fec820fadb88001edba9da3906203a7b860b4a63c159c66fa31836` | `82abaa23e09117edea58a3aa677ad5420920cd688fb9301a2b49a83f26922791` | 387 |
| added | `artifacts/leviathan-build/market-data-buildout/api-anything-001-c1/index.md` | `-` | `c92beb7b7e5edd3957ad0db9cc95795270b31415dd17612a98c06afaaeb0d777` | 6822 |
| added | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/api_anything_templates.py` | `-` | `af03d8d6893474d6799cf51b38aa5d4a308f5b8cbf3dba2f1bcdc50e9635818a` | 5077 |
| added | `qa/acceptance/API-ANYTHING-001/aa_harness.py` | `-` | `16646aa5edd7d23b8d2d3273b4e88be0c3fb9603191f3deca5ebde40a03159a8` | 15700 |
| added | `qa/acceptance/API-ANYTHING-001/conftest.py` | `-` | `6abcea4ec999a2cec70343a5f607f66188d6e2f4af92573572afa7d678ab26c4` | 6479 |
| added | `qa/acceptance/API-ANYTHING-001/mutation-results.json` | `-` | `d7457ea56d605a237f23d8b7bc33104961b9ce9f4c24ddb26f2f53c394422739` | 7748 |
| added | `qa/acceptance/API-ANYTHING-001/node_units.test.mjs` | `-` | `6dfd65e0d9571c7c17ad808a07f875f68595a9b860e2af1215214b950409b979` | 11645 |
| added | `qa/acceptance/API-ANYTHING-001/run_mutants.py` | `-` | `88b596b594233e35db2b81149c58d92bdc90889252c90e4a5f97a10bf653e4fa` | 6817 |
| added | `qa/acceptance/API-ANYTHING-001/test_01_transport_and_no_templates.py` | `-` | `accf960e5da1f3a0dade090ce10a0c88cb24b6df58e3fc68380aeb2cee51db24` | 15245 |
| added | `qa/acceptance/API-ANYTHING-001/test_02_templates_repair_challenge.py` | `-` | `0808bd8fc3e8aa275c9871577fc03232c626dac0441af38dbbc57e0b342004f9` | 17769 |
| added | `qa/acceptance/API-ANYTHING-001/test_03_real_vendor_loopback.py` | `-` | `9a0806b968d77aa72d627004c819ad451bee5c9a8b0d84d0e780fe1940baacc6` | 7831 |
| added | `qa/acceptance/API-ANYTHING-001/test_04_client_records_failclosed.py` | `-` | `7abcf0756c3fd18a072494946b2dbeb3cb847c16a193fdc8f6552882f7c435f0` | 19006 |
| added | `qa/acceptance/API-ANYTHING-001/test_05_node_units_and_ledger.py` | `-` | `c211caeba2b5725bdf02e8ae2be1d4a8f9348933fe75aea1e169072bfdb639f8` | 1997 |
| added | `qa/handoffs/API-ANYTHING-001/cycle-1-start.json` | `-` | `f16febaebf856882d052b8df5f3d7876816bb3c23e8243bedf117a11be05501c` | 477382 |
| added | `services/public-collector/patches/api-anything-runtime.patch` | `-` | `2354cdb5660eb933ee82b6b52d385eaf2744a86c53e8da42e055150a421b665a` | 8044 |
| added | `services/public-collector/runtime-manifest.json` | `-` | `0db2f97a57072019548736554d5691278cafb6b7f1d1e77fdd720d5ce8c9bfb4` | 366 |
| added | `services/public-collector/scripts/build-vendor.mjs` | `-` | `b369ce8c5ff5732bdae2f6402ee4df9db1bd40d735315fcb17750d072bc9636b` | 3512 |
| added | `services/public-collector/scripts/secure-pinned-registry.ps1` | `-` | `b96871482446978c59a62627005fb79dd27f933eb62e9e3a0c00f4cebe33f2aa` | 1025 |
| added | `services/public-collector/src/main.test.ts` | `-` | `abbef6331a4f2f99becad937ec0854111a1d6ea51915f45114b3f1e3fab200f3` | 2790 |
| added | `services/public-collector/src/rate-limiter.test.ts` | `-` | `3d813090f8df6d81104ce048ac9f205937ffef58960fd78b9cb28dec6e483a87` | 1815 |
| added | `services/public-collector/src/rate-limiter.ts` | `-` | `c96c276b74991f0a523d08d92c0c76dbcdd8b26197537b8c710cc82643157477` | 3290 |
| added | `services/public-collector/src/robots.ts` | `-` | `6ab00a83ee01a8ee309cf48a495f9b94a955bb71d575e029beac06e02af36c16` | 5341 |
| added | `services/public-collector/templates/PINNED.json` | `-` | `169c5956dc9da097d39b78824ca59831354fb42bfe76dd671fc2f0a1614352f5` | 2843 |

## Exclusions and shared files

- Excluded generated/temporary paths: `.git`, `.venv`, `node_modules`, `target`, `dist`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.scratch`, `qa/integration-backups`, and `.wrangler/cache`.
- The copied `.wrangler/cache/wrangler-account.json` was removed before work. Its content and hash are intentionally omitted from this ledger.
- Excluded from this lane diff because they are byte-identical to canonical PUBLIC-DATA-001 files: `public_sources/__init__.py`, `public_sources/registry.py`, `public_sources/sources.py` (verified byte-for-byte).
- Cycle 1 acceptance inputs under `qa/acceptance/API-ANYTHING-001/` were copied unchanged from frozen Cycle 0; the ten files were hash-compared with zero mismatches.

## Verification

- Frozen coordinator acceptance findings: **6 passed** (`uv run pytest qa/acceptance/API-ANYTHING-001 -k finding`; 151 deselected, 3 expected xfails, 1 xpass).
- Market Data: 1,149 passed; client-specific tests: 20 passed. API: 1,475 passed, 1 skipped. Store: 548 passed, 2 skipped. Vault: 163 passed, 36 skipped.
- Core sequential rerun: **6,578 passed, 10 skipped, 1 xfailed** (5 warnings; 558.46 seconds). One earlier run had a single activity-read failure; the isolated rerun and sequential rerun passed.
- Mypy default/Linux/Darwin: **442 source files passed in each mode**. Ruff (`--extend-exclude qa/integration-backups`): passed.
- Sidecar: clean `npm ci --ignore-scripts`; **8 Node tests passed**. Both lockfiles have `resolved` and `integrity` for all registry packages (67 root and 15 vendor entries); local file links are excluded from registry-package counts. `playwright-core` is exactly 1.63.0.
- Vendor pin: api-anything commit `fe5cca70fe145634e49a1c9ba1f3e8250b291bea`; patch SHA-256 `2354cdb5660eb933ee82b6b52d385eaf2744a86c53e8da42e055150a421b665a`.

## Disposition

Cycle 1 implements the cycle-0 review/acceptance remediations and is frozen for coordinator re-review. The acceptance/review verdict is pending their rerun. Live learning and source-site fixture capture remain paused. No templates are pinned; all five operations abstain as unpinned/unavailable. No P3 finding was intentionally deferred. Direct Playwright support on macOS 11.7 Big Sur remains unverified; replay-only mode is the supported fallback.
