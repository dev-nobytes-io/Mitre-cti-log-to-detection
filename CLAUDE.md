# Repository conventions for Claude

## Chunked-PR development pattern

This project uses a **chunked, stacked, test-first** development workflow.
Use it for any non-trivial change.

### When to chunk

A "chunk" is a single conceptual unit of work that:

- Leaves the app in a working state on its own.
- Is independently reviewable in <300 LoC of meaningful change.
- Adds or updates the e2e tests that cover whatever it introduced.
- Has its own commit and its own PR.

If a request would land >500 LoC of meaningful change, or touches >3
unrelated subsystems, plan the work as multiple chunks before writing
code. Use `/plan` or write a plan file under `/root/.claude/plans/` with
one heading per chunk.

### Stacking PRs

Open one PR per chunk. If chunk N is not yet merged when chunk N+1 is
ready:

1. Branch chunk N+1 off chunk N's branch (not off `main`).
2. In `mcp__github__create_pull_request`, set `base` to chunk N's
   branch so the PR diff stays scoped to N+1's changes only.
3. Note the dependency in the PR body ("Stacked on PR #X. Merge that
   first.").

When a stacked PR's base is merged + deleted, GitHub will need the
follow-up PR's base retargeted to the new default branch. Do that
manually if the user hasn't.

### Per-chunk checklist

For every chunk, before opening the PR:

1. **Code change** — implement the chunk and only the chunk.
   - Keep legacy code paths alongside new ones for one chunk before
     removing them in a later chunk. Removes are their own chunk.
   - Don't write speculative back-compat that no caller exercises.
2. **Local test run** — `node tests/run.mjs` must show every test green
   (including the new ones). The runner spins up
   `python3 -m http.server 8765` and runs Playwright against it.
3. **Add a test** for the chunk's new behaviour. The bar is "if I broke
   this, would a test fail?"
   - Inventory / UI changes: test in `tests/e2e/02-inventory-import.test.mjs`
     or `tests/e2e/04-mobile-and-tabs.test.mjs`.
   - Coverage / threats: `tests/e2e/03-threats-and-gaps.test.mjs`.
   - Parser / fixture changes: `tests/e2e/01-init.test.mjs`.
4. **Commit** with a `<verb> <subject> (chunk N)` first-line and a
   bullet-style body listing each file's substantive change. End with
   the session URL footer.
5. **Push + PR** via `gh` is not available; use the
   `mcp__github__create_pull_request` MCP tool. The repo's default
   branch is `claude/mitre-cti-inventory-app-ibnsH`, **not** `main`.
6. **Wait for CI** before starting the next chunk
   (`mcp__github__pull_request_read` with method `get_check_runs`).
   Do not pile commits onto an already-pushed PR — open a stacked PR
   instead.

### Test infrastructure gotchas

- `tests/harness.mjs` tries `/opt/node22/lib/node_modules/playwright/index.mjs`
  first (sandbox path) then falls back to standard module resolution
  (`import "playwright"`). Keep both paths working — CI and the local
  sandbox use different ones.
- The test runner uses `--test-timeout=60000`; if a Playwright wait
  takes longer than that, split the assertion or page state.
- Persona test expectations are pinned numbers (e.g. `minScored: 17`).
  When a fixture changes, update the matching row in the `PERSONAS`
  array.

### What "lit" means in this app

Specific to this codebase: a detection strategy is "lit" iff at least
one of its analytics is lit; an analytic is "lit" iff every required
log source has score > 0. The aggregator (`min` default, `avg` toggle)
turns those scores into a single 0..5 analytic score. Don't conflate
"covered" (legacy v1: any covering data component scored) with "lit"
(v2: full chain validates).

### Git operations

- Branch naming: `claude/<topic>` (matches existing patterns).
- Default branch is `claude/mitre-cti-inventory-app-ibnsH`. PR base
  defaults to that or to the previous chunk's branch when stacking.
- Don't force-push to a published branch unless the user asks.
- Don't merge PRs from this side; the user merges async.
