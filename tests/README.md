# Tests

End-to-end Playwright tests that drive the static site in real Chromium.

## Run locally

```sh
node tests/run.mjs
```

The runner starts `python3 -m http.server 8765`, runs every
`tests/e2e/*.test.mjs` file via `node:test`, and exits non-zero on
failure.

## What's covered

| File | Verifies |
|---|---|
| `e2e/01-init.test.mjs` | Vendored `js-yaml` + `mermaid` load. Offline ATT&CK auto-loads on first visit and falls back when `raw.githubusercontent.com` is blocked. |
| `e2e/02-inventory-import.test.mjs` | Each `samples/persona-*.yaml` populates the inventory UI (summary card + scored row count + components-covered count). Re-importing the same file via the same picker still works. Importing while on Detection Strategies refreshes that tab without a manual click. |
| `e2e/03-threats-and-gaps.test.mjs` | Each `samples/threats-*.yaml` selects groups in the picker. Gap analysis populates when both an inventory and a threats file are imported. |
| `e2e/04-mobile-and-tabs.test.mjs` | At 390 px the tab strip is replaced with a `<select>` and there's no horizontal overflow. Every tab activates without page errors. Desktop layout still hides the dropdown. |

## CI

`.github/workflows/test.yml` runs the suite on every push and PR. It
installs Chromium via `npx playwright install chromium` (cached), then
shells out to `node tests/run.mjs`.

## Adding a new test

1. Drop a `tests/e2e/NN-name.test.mjs` file using `node:test`.
2. Import helpers from `../harness.mjs` (`newPage`, `bootApp`,
   `activateTab`, `importInventory`, `importThreats`, `readStats`).
3. `await page.context().close()` at the end of every test.
