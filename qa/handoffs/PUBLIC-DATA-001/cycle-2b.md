# PUBLIC-DATA-001 cycle 2b delta ledger

## Baseline and scope

This delta is measured against `public-data-001-c2-frozen`. The baseline manifest [cycle-2b-start.json](cycle-2b-start.json) contains 1,565 files and has SHA-256 `1d7e7fbce6ac2cbdba8e26d3f8d607a944b2a9af73bd7af5e4ac37fb22049fc9`. The ledger lists all seven changed or added repository files. The ledger itself is excluded from its own hash table.

Coinbase's official Advanced Trade public product endpoint documents futures `open_interest` at `future_product_details.open_interest` and `future_product_details.perpetual_details.open_interest`. The US-filtered product catalog is unauthenticated. Since the schema has no source observation timestamp, the adapter uses local fetch time as `fetched_at`, conservative `as_of`, and first-observed `knowable_at`. CME BTC/ETH basis and open interest from licensed Databento remain a separate INTEL positioning input.

## Changed and added repository files

For modified files, the first hash is the c2 frozen SHA-256 and the second is the 2b frozen SHA-256. `ABSENT` means the file did not exist in the c2 baseline.

| State | Path | C2 SHA-256 | 2b frozen SHA-256 |
|---|---|---|---|
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/__init__.py` | `169cd11f106b9500296334857602576ab4b60b17473e127ac5c0c8f1957469de` | `9fde821dbbbf4c95a7f4e3f5b34bc4a57688a2477bb51700962c2446037dd686` |
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/registry.py` | `f7e4ae882f0a8d70539c5118fa73b7842d920c260eeec193aa10b55558d63847` | `c1e68a073c67c69f01b7f722d0c9370b3267f911d6f9b68605d69b74e55df930` |
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py` | `b7aaba8c7df4e5220898669ef596939a973a826ce43404109a0f31aab636defb` | `cc4b6a01c1b0ed6acf333773a3160c16024e8ffd7cabcf7dd786d5a3a033c371` |
| Added | `packages/leviathan-market-data/tests/fixtures/public_sources/coinbase-futures-open-interest.json` | `ABSENT` | `07c5a6adf367c36ba08fdf883ef56c33dc6999578c8627a65c81cee02eb307ac` |
| Modified | `packages/leviathan-market-data/tests/test_public_sources.py` | `e9d1a82e713ac09c37cf9f6a4b9904db390322f9b9243f961edbaac84f5aa0be` | `d331744f3c14758affc77c69dab1ac6dcefccf618ee3cee7f1292f4b3a6f4178` |
| Added | `qa/acceptance/PUBLIC-DATA-001/test_public_data_cycle2_acceptance.py` | `ABSENT` | `99cc2f10affc14ba03b67dc2c0c46b713f17af0e35c8591426862396f35a22e2` |
| Added | `qa/handoffs/PUBLIC-DATA-001/cycle-2b-start.json` | `ABSENT` | `1d7e7fbce6ac2cbdba8e26d3f8d607a944b2a9af73bd7af5e4ac37fb22049fc9` |

## Verification

| Check | Result |
|---|---|
| `pytest packages/leviathan-market-data/tests -q` | PASS (1,168 passed) |
| `pytest qa/acceptance/PUBLIC-DATA-001/test_public_data_cycle2_acceptance.py -q` | PASS (7 passed) |
| `mypy` | PASS (443 source files) |
| `mypy --platform linux` | PASS (443 source files) |
| `mypy --platform darwin` | PASS (443 source files) |
| `ruff check --extend-exclude qa/integration-backups .` | PASS |

Tests use recorded fixtures/fake transport; they make no provider network calls.

## Updated artifact hashes

| Artifact | SHA-256 |
|---|---|
| `public-data-001/discovery/index.md` | `46724843ddaa3403e2335823a8fceab4af23fee91b10b1b9a417d44c7a8f2f85` |
| `public-data-001/cycle-2b/index.md` | `568e2f0c14a8373ea0f9de24b05de105d881bf30822e52e96d4a7507549ec4f3` |
