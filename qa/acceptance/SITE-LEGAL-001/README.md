# SITE-LEGAL-001 acceptance suite (independent reviewer)

New files only; no writer file is modified. Everything runs on temp copies of `workers/site`.

| File | Purpose |
|---|---|
| `acceptance.test.mjs` | 137 `node:test` cases: ROUTE, HDR, 3P, LINK, GATE, MOBILE, LEGAL, ACC, CLAIM groups |
| `helpers.mjs` | stages a temp copy, runs the strict build, starts the **real** Workers runtime (`wrangler dev --local`) |
| `mutants.mjs` | 16 mutants applied to a "patched baseline" (writer tree + the P1-1 reference fix) |

## Run

```
# wrangler is NOT a dependency of the writer's package; install it anywhere and point at it (fail closed otherwise):
npm i --no-save wrangler            # in any scratch dir
set SITE_ACCEPT_WRANGLER_JS=<scratch>\node_modules\wrangler\bin\wrangler.js

node --test qa/acceptance/SITE-LEGAL-001/acceptance.test.mjs
node qa/acceptance/SITE-LEGAL-001/mutants.mjs                # mutation run (~12 min)
node qa/acceptance/SITE-LEGAL-001/mutants.mjs --writer-only  # pass/fail list on the writer's tree as-is
```

Optional env: `SITE_ROOT` (site dir to test), `CANONICAL_REPO` (read-only repo for `CLAIM` tests), `DEPLOY_SCRIPT`.
Facts used for runtime/content tests are obviously fake (`example.test`) and exist only in temp copies.

Phone width: the `MOBILE` tests are static CSS/meta checks. The reviewer also measured all 10 pages at 320 px and 375 px in a real browser (iframe, `scrollWidth == clientWidth`); that measurement is recorded in the verdict, not automated here.
