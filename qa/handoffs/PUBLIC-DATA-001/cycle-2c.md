# PUBLIC-DATA-001 cycle 2c delta ledger

## Baseline and scope

This delta is measured against `public-data-001-c2b-frozen`. The baseline manifest [cycle-2c-start.json](cycle-2c-start.json) contains 1,569 files and has SHA-256 `2293ce99ca92aac2fdebaecb031805aa9c476fa15914ce1d6b1bf7ded421580e`. The ledger lists all four changed or added repository files. The ledger itself is excluded from its own hash table.

The Coinbase OI parser now chooses nested perpetual open interest by explicit key presence and falls back to the top-level futures field only when the nested value is `None`. Thus a nested numeric zero is preserved and takes precedence over a different top-level value. If both fields are missing, it raises `SCHEMA_MISSING_COLUMN`. A scan of `sources.py` found no other truthiness fallback that selects a numeric market value; other `or` uses are validation, string/date fields or optional configuration defaults.

## Changed and added repository files

For modified files, the first hash is the c2b frozen SHA-256 and the second is the 2c frozen SHA-256. `ABSENT` means the file did not exist in the c2b baseline.

| State | Path | C2b SHA-256 | 2c frozen SHA-256 |
|---|---|---|---|
| Modified | `packages/leviathan-market-data/src/leviathan_market_data/public_sources/sources.py` | `cc4b6a01c1b0ed6acf333773a3160c16024e8ffd7cabcf7dd786d5a3a033c371` | `2b0b5c152c2fbc5efd853f5a666ba5685a460d9b8e59855bb6d1f1a64133e634` |
| Modified | `packages/leviathan-market-data/tests/test_public_sources.py` | `d331744f3c14758affc77c69dab1ac6dcefccf618ee3cee7f1292f4b3a6f4178` | `ecc6d1b1f2c10387b9f9ed5fa0bc8e96ff9b457a84acf643f72de23ee6dc8fd2` |
| Added | `qa/acceptance/PUBLIC-DATA-001/test_public_data_cycle2b_acceptance.py` | `ABSENT` | `3931191653bc715b555dba71a7abf0bc8dcdb08acb0f7cef959dbf2a5c47b871` |
| Added | `qa/handoffs/PUBLIC-DATA-001/cycle-2c-start.json` | `ABSENT` | `2293ce99ca92aac2fdebaecb031805aa9c476fa15914ce1d6b1bf7ded421580e` |

## Verification

| Check | Result |
|---|---|
| `pytest packages/leviathan-market-data/tests -q` | PASS (1,170 passed) |
| `pytest qa/acceptance/PUBLIC-DATA-001/test_public_data_cycle2b_acceptance.py -q` | PASS (4 passed) |
| `mypy` | PASS (443 source files) |
| `mypy --platform linux` | PASS (443 source files) |
| `mypy --platform darwin` | PASS (443 source files) |
| `ruff check --extend-exclude qa/integration-backups .` | PASS |
