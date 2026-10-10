# Acceptance suite (API-ANYTHING-001) - current entry point

Run: `pytest qa/acceptance/API-ANYTHING-001/cycle2` (needs the collector `node_modules`; builds a scratch copy, never writes the frozen tree).
Mutants: `python cycle2/run_mutants_c2.py` (43 mutants).

The cycle-0 files (`test_01..05_*.py`) and `cycle1/` are retired (not collected): they encode the generic `extract: data`
recipe and the removed AA_CONTROL seam.  Their rules map to:

| Rule / legacy file | Current coverage |
|---|---|
| private stdio, no network listener (01, 03) | test_c2_client.py, test_c2_node_static.py |
| isolated Chrome profile (02) | test_c2_node_static.py, node_units_c2.test.mjs |
| pinned versioned templates + canary (02, c1 pins) | test_c2_pins_policy.py, test_c4_learn_recipes.py |
| bot-check hand-off, no auto-solving (02) | test_c2_challenge_replay.py, test_c4_learn_recipes.py (6 markers), test_c3_p2.py |
| typed fail-closed client + provenance (04) | test_c2_client.py |
| no learned templates => TEMPLATE_UNAVAILABLE (01) | test_c2_pins_policy.py |
| rate limiter / cadence / robots / host allow-list (c1) | test_c2_limiter_candidates.py, test_c2_pins_policy.py |
| ledger and import containment (05) | test_c2_node_static.py |
