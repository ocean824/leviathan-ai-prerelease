# MD-RUNTIME-001 implementation freeze — cycle 1

**Status:** cycle-1 delta frozen; independent acceptance passed; ready for limited review. Live-provider smoke remains outstanding.  
**Scope:** cycle-1 fixes are limited to DBN open-ended mapping intervals and off-loop, non-retained credential resolution. No `main.py` change, provider calls, real credential resolution, or canonical-repository writes were made.

## Cycle-1 adjudicated fixes

- **DBN mapping interval sentinel:** pinned `databento-dbn` exposes `UNDEF_TIMESTAMP` for nullable `SymbolMappingMsg.start_ts` and `end_ts`. A missing start is normalized to the lower timestamp-domain bound (0); a missing end is retained as the unsigned sentinel above every accepted event timestamp. A later remap truncates a prior open-ended interval at the new start. Non-sentinel values outside the signed timestamp domain and reversed/empty ranges remain invalid. The runtime looks up the already-ingested mapping message by its stable start/input/output identity, so a later map decoded in the same batch does not make the earlier message ambiguous.
- **Vault resolution:** live reconnect/session paths call the injected blocking resolver through `asyncio.to_thread`; no key cache is stored on `MarketDataRuntime`, so each new connection resolves once and the prior key is not retained between sessions. A slow-resolver test verifies unrelated asyncio work progresses while resolution is blocked and verifies a later resolution calls the resolver again. Historical reads keep resolved key material in a per-job mapping passed to the worker read; it is not retained on the runtime.
- Independent acceptance file was not modified: `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py`, SHA-256 `A62171BA69C7D03999E8F0944CB39ACE0CDB1AA67538B68799747E5DAB1616CB`; targeted result after delta: **14 passed**, one existing Starlette/httpx deprecation warning. Acceptance author reported all six mutation checks killed and no new findings.

## Design and lifecycle

The approved design is `artifacts/leviathan-build/market-data-buildout/md-runtime-design/index.md` (design SHA recorded by coordinator as `B8560ECC…`). `Wave35MountDependenciesV1` accepts an injected runtime config and backfill executor. Startup precedence is injected config, bounded strict config file under the API's state/data root, then explicit environment path; absent/invalid configuration remains `NOT_CONFIGURED`. W35 owns async runtime start/close in its existing lifespan seam. `main.py` is byte-identical to current canonical (`424F4502497ED264BF491DBF10264B00B3499A3D55498AF4D530222265D47DB8`).

The runtime uses direct provider transports. Databento live performs CRAM auth over the provider TCP protocol with an in-process vault-resolved key; no key or CRAM response is logged. Databento `SymbolMappingMsg` records populate a per-session `MappingRegistry`; reconnect discards and rebuilds mappings, and unmapped instrument IDs degrade/drop rather than being guessed. Massive supports configured trades, quotes and aggregates, without L2. Per-client chart queues are bounded; overflow drops backlog and sends a fresh snapshot. Chart state exposes stale/disconnected conditions.

The async runtime directly reuses the existing pure freshness policy/evaluation functions (`FreshnessPolicyV1` and `evaluate_freshness`) to avoid blocking the event loop and leaves `LiveSubscriptionKernel`'s public sync API unchanged. Socket reads are async; decode/commit uses bounded queues and degrades on pressure. No sync socket or file read, or `time.sleep`, is used in the live hot path.

## Historical bridge and limits

`HistoricalBackfillExecutor` uses the existing `DatabentoHistoricalAdapter.read(DatabentoReadSpec)` and existing Massive historical adapter. Databento requires a configured `max_estimated_usd` and rejects if absent before `read`; the existing adapter's `metadata.get_cost` preflight is the sole cost check and existing record/window caps remain active. Massive uses a small injected-port transport implemented with stdlib `urllib`, pinned to `https://api.massive.com` and allowlisted paths, bearer authorization, bounded response reads, timeout, redirect refusal, and content-free errors. Provider disabled/missing key yields per-provider `NOT_CONFIGURED`. Backfill work is bounded by configured queue/concurrency/spend caps. Credentials are resolved only through the vault resolver seam and are not part of config or the example.

The chart WebSocket is loopback-only and project/principal-scoped. Latest-event reads are keyed by venue/provider, instrument and data type and carry source time and freshness. Historical `metadata.get_cost` is not repeated by the runtime.

## Dependency verification

Added `databento-dbn==0.71.0` with Python `<3.15` marker; no full Databento SDK. Dependency metadata reports `Apache-2.0` (wheel `License-Expression`, inspected from the package metadata). Wheel hashes recorded from the lock/package metadata:

| Platform wheel | SHA-256 |
|---|---|
| Windows x86_64, CPython 3.14 | `b5ebcb1ef3c9cabc4c598ef54668dd4e81a555790eed70c94d697af7d3557c4f` |
| macOS universal2, CPython 3.14 (arm64 + x86_64) | `48c0f13003e7012386d4998e1a60441d0f24d12ae2849b914070d5f381cf3874` |
| macOS x86_64, CPython 3.14 | `b2cc4a6afcda102f0c9bd26e4b1f6662e77f893a2415d725025f0e5a5042236b` |

The current canonical Mac Phase A `keyring` Darwin marker was preserved. Worktree `uv.lock` resolves both the Mac keyring change and this DBN pin. Worktree lock SHA is `815C94A6FADBE1C8C7BEF19258B1EF99D259715CF4B5BFA8EAB0F3DAADFAF4E5`; current canonical lock SHA at comparison was `8217F08BCDD0E017AF9947517AD8A25BC0508EA55DFAF05F617CC989D7692C2A`. Market-data package metadata SHA is `9D68C4374B4CEEE60AC19888EEBAA80413A8851CB166CEA62725F4BA5E7DE1CF`. Vault package metadata retains current canonical SHA `F4159B7174D197AFE7D3F446013F178E9962BB4F2CECE262247DE55AA40CD561` and Darwin `keyring>=25.6,<26` marker. Root `pyproject.toml` is unchanged from canonical (`26F2C0ABC7A22A21E6214096E75BE69C876D0B3ED8171C9370C5F2F3A1474251`).

Protocol/record references verified: [Databento Rust live protocol](https://github.com/databento/databento-rs/blob/main/src/live/protocol.rs), [Databento Python gateway](https://github.com/databento/databento-python/blob/main/databento/live/gateway.py), and [DBN `SymbolMappingMsg` fields](https://docs.rs/dbn/latest/dbn/record/struct.SymbolMappingMsg.html). The project code implements an injectable transport and synthetic fake-gateway tests; it does not connect to a provider here.

## Verification

- `uv lock --check` — passed; 58 packages resolved.
- `uv run --locked pytest apps/api/tests packages/leviathan-market-data/tests qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py -q` — **2,580 passed, 1 skipped**, 15 warnings. The run used this worktree's API, market-data, core, store and vault `src` directories plus `C:\Users\XYRASYSTEMS\AppData\Local\Temp\md-runtime-001-deps` on `PYTHONPATH`; DBN was installed to this temporary target and not into the canonical environment.
- `uv run --locked mypy` — passed; 428 source files.
- Scoped Ruff check and format check — passed for owned Python sources/tests.
- `npm.cmd test -- --maxWorkers=1 --reporter=dot` in `apps/terminal` — **1,399 passed, 1 skipped**.
- `npm.cmd run lint` — passed with one pre-existing React hook dependency warning at `src/wave33/marketData/PaperMarketDataHealthView.tsx:154` (`refreshVenues`).
- `npm.cmd run build` — passed; live workspace is code split.
- Deterministic fake-transport benchmark (1,000 records): receive→commit p50/p95/p99 = **1.499/1.949/1.989 ms**; source→commit = **2.998/3.898/3.978 ms**. These are synthetic measurement results, not a latency SLA or real-market result.

No live smoke was run, so provider entitlements, purchased plan coverage, actual source-to-cache latency and installed-app startup remain to be verified by the coordinator's post-integration smoke. No credential was resolved and no external provider was contacted.

## Snapshot and drift

Canonical repo: `C:\Users\XYRASYSTEMS\TRAYCER MASTER TEMPLATE\XYRA-MASTER\projects\XYRASYSTEMS\LEVIATHAN AI\repo`. Captured comparison census (standard exclusions: `.git`, virtual environments, node_modules, generated build/cache trees): canonical **1,613 files**, fingerprint `30dbaa9d442127f106e126bf4efe43b83c17d3e0cff9d8533881fde60829be0a`; worktree **1,599 files**, fingerprint `777a6a2f76ccd69014ff11fdfa6fda260aa6e7d8922e095d32b4532ab24c8c6d`; canonical-only 32, worktree-only 18, differing 24. This is not represented as a byte-identical full-tree sync: concurrent wave work and post-start canonical drift remain outside this task. We preserved those non-owned bytes and rebased the shared dependency metadata explicitly. At freeze comparison, canonical `main.py`, root `pyproject.toml` and vault `pyproject.toml` matched worktree exactly. `wave35_mounts.py` and terminal `App.tsx` were re-hashed against current canonical; their differences are this task's intended edits, not Mac changes.

Canonical start/current baseline references: `wave35_mounts.py` `E02924CD109568E3E9DE21D4C2EA4507E0AF6C85E257589C1DCCC47C94CBBC99`; router `market_data_paper_v1.py` `362865C065E4EB0CDE530C33C025D19075ECF1BBAAF340414828F1C80F5E73A7`; terminal `App.tsx` `A8F39DCEE18DAC5541E2C900E32A194D9C271CE82C5ECC4413C3E31894A52201`; existing `providers/databento.py` `B7C8CE2F09BEE7C7A969D54E815D4007BBF426AC7727A574A35CC215CCDE1139`. The latter provider adapter is reused and unchanged. At the freeze comparison, canonical current `wave35_mounts.py` remained `E02924CD109568E3E9DE21D4C2EA4507E0AF6C85E257589C1DCCC47C94CBBC99` and canonical current `App.tsx` remained `A8F39DCEE18DAC5541E2C900E32A194D9C271CE82C5ECC4413C3E31894A52201`; their worktree hashes are in the frozen file table above. The current canonical `main.py` hash is `424F4502497ED264BF491DBF10264B00B3499A3D55498AF4D530222265D47DB8` and matches worktree exactly.

The cycle-1 recheck against current canonical confirms `uv.lock` differs only by the `databento-dbn==0.71.0` package block and the market-data dependency edge. Canonical `uv.lock` is `8217F08BCDD0E017AF9947517AD8A25BC0508EA55DFAF05F617CC989D7692C2A`; worktree lock is `815C94A6FADBE1C8C7BEF19258B1EF99D259715CF4B5BFA8EAB0F3DAADFAF4E5`. The canonical Darwin `keyring` entries remain in both lockfiles. `uv lock --check` passes. Canonical `main.py`, root `pyproject.toml`, and vault `pyproject.toml` still match worktree byte-for-byte; current canonical `wave35_mounts.py` and `App.tsx` hashes were rechecked and remain the baselines recorded above.

## Frozen file hashes

SHA-256 values below are worktree bytes at freeze. This table includes all task implementation/test/config/dependency files, touched terminal chart files, and the existing historical adapter files used by the bridge.

| Path | SHA-256 |
|---|---|
| `uv.lock` | `815C94A6FADBE1C8C7BEF19258B1EF99D259715CF4B5BFA8EAB0F3DAADFAF4E5` |
| `pyproject.toml` | `26F2C0ABC7A22A21E6214096E75BE69C876D0B3ED8171C9370C5F2F3A1474251` |
| `packages/leviathan-vault/pyproject.toml` | `F4159B7174D197AFE7D3F446013F178E9962BB4F2CECE262247DE55AA40CD561` |
| `packages/leviathan-market-data/pyproject.toml` | `9D68C4374B4CEEE60AC19888EEBAA80413A8851CB166CEA62725F4BA5E7DE1CF` |
| `apps/api/config/local-paper-market-data.example.toml` | `B4625FC74E639D7B54E414DA048171C104C6F00F97DE0354E972C340A3E086DA` |
| `apps/api/src/leviathan_api/market_data_backfill.py` | `E3E2FC93271DF912834035E75B7B982CA2F2E2E4BE53A8BF85E5AEB31E0B956C` |
| `apps/api/src/leviathan_api/market_data_runtime.py` | `6F1B21B89C3E93B693874E22E845318CBFFEB9835132F12C0BF21F09D850F6E4` |
| `apps/api/src/leviathan_api/market_data_runtime_config.py` | `D1E975834654CF42286C9B108F9F9D325CA92F9CCCB30FA234D858058D6C7313` |
| `apps/api/src/leviathan_api/wave35_mounts.py` | `AB5C25EF5A3BCD74934ECD31976FC05B4B724C675959AB4AD77460B6BEB4360B` |
| `apps/api/src/leviathan_api/routers/market_data_paper_v1.py` | `3429894DEC8FC233491665E27BC939872B345100501E1CF39019D45A329CDCF8` |
| `apps/api/tests/test_market_data_runtime.py` | `F67C1DEBA0AEF703900DFEAFC74D8FD2C23E62DBF0549118365C338C4900303F` |
| `apps/api/tests/test_market_data_runtime_config.py` | `1509CC4C118D98A58F2C60A0C193CE24B478DA5EFBB4941C3AA0121B2BD9ED39` |
| `apps/api/tests/test_market_data_paper_v1.py` | `A8FFFAFB88CED585E84B0BDFC03C62C19CEB8A4DA427D7BF11BCF1B30E270501` |
| `apps/api/tests/test_wave35_mounts.py` | `5E2CA7457EEBCE4FCD77EB37E718A1AC0156B32C17C28BEF5AA808AE4B4127AD` |
| `packages/leviathan-market-data/src/leviathan_market_data/live/latest_store.py` | `92516FE8C5852DB44145EB18FA9C74147AA408E4A536E09923DC34F30A58E4AF` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento.py` (reused) | `B7C8CE2F09BEE7C7A969D54E815D4007BBF426AC7727A574A35CC215CCDE1139` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_live.py` | `46E8BC89D5D3BDEB806E3784797D8C8FECEC0819CEDE751F75E0BEDB19E2190E` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/databento_mapping.py` | `1CDC454DA1043F5307308F9326CA770F5368983E10E2905B307166B1F70133DE` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive.py` (reused) | `D6C18858FFE98F5C46040409C954BE496C79D3BAA4F3FA2DACEFA6D5E15859F3` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_live.py` | `C339A663B791353EF5EF18B1B7DBE9D197FC6B8B65BA63238B0D4D2EDD3CEE50` |
| `packages/leviathan-market-data/src/leviathan_market_data/providers/massive_transport.py` | `BCFDCBEA4F265BC8ECAE0C136535D42F0895087F9769CF53127CC1314A4F1365` |
| `packages/leviathan-market-data/tests/live/test_runtime.py` | `BF3168F0439DDF49F241BB9CEFBFE407607239FB451EC960F04CF8C5B5BA7041` |
| `packages/leviathan-market-data/tests/live/test_databento_mapping.py` | `C17B4D50AD85308303DAEE5542C8CB6F3442097C9426076DE8E73CB0B0BA7622` |
| `packages/leviathan-market-data/tests/test_massive_transport.py` | `069A127EAD9A71C936E58B9DA10B9AFB95E5D28B12BBE9FF4AA8CEE817B127F9` |
| `qa/acceptance/md_runtime_001/test_md_runtime_001_acceptance.py` | `A62171BA69C7D03999E8F0944CB39ACE0CDB1AA67538B68799747E5DAB1616CB` |
| `apps/terminal/src/App.tsx` | `A248204B00C6575B943E1CBEAC04351AA5C707D2D8D7E6BD562030B2E0395AE1` |
| `apps/terminal/src/wave34/charts/ChartPort.ts` | `D8CA91966195E87470C08707DA75B31AF62620000D2549E193A8C82B5B93108F` |
| `apps/terminal/src/wave34/charts/LiveMarketDataWorkspace.tsx` | `A253F7F1A99CFF00D5FB4B25F7DD3AF6A635AFC8BD0AEB66BD09601BDD4EC861` |
| `apps/terminal/src/wave34/charts/model.ts` | `BE7F93A6C21D505A8C028E2F0A8089FED408B4C083D69DD81B58D6AA1D776CB8` |
| `apps/terminal/src/wave34/charts/PriceDepthFootprintView.tsx` | `9B1B296B8ED2A5EE143E5DF27FEF0BD6834A866296DBD76DEC66C1705354265F` |
| `apps/terminal/src/wave34/charts/test/charting.acceptance.test.tsx` | `A2E713711F76F7C0BF0C2B56C5A60D4A30946A836A0B0A0F0C47B6394542690F` |
| `apps/terminal/src/wave34/charts/test/chartPort.unit.test.tsx` | `2A53F351A09C8378F34934A41C73CC1A9A7E3E184CF587D5A6EAB7F283D0BAE0` |
| `apps/terminal/src/wave34/charts/test/liveMarketData.test.tsx` | `1F5DBF404A90D453752A9018F286D02E7C32C0607B2F3C2081E9D1BD01584C17` |

