// Chunk 2 of the inventory-merge refactor: scaffold the unified Log
// Inventory panel behind a feature flag (?merged=1 query param OR
// localStorage.MERGED_INVENTORY=1). Old tabs 2/3/4 stay default-on
// when the flag is off, so the scaffold ships without disturbing
// the live UI. This test pins both modes.
//
// Later chunks (3-5) will extend this file with hierarchy /
// diagram / analytic / strategy / detected-TTP assertions.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, ORIGIN, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

async function bootMerged(page) {
  await page.goto(`${ORIGIN}/?merged=1`, { waitUntil: "networkidle" });
  await page.waitForFunction(() => {
    const s = document.querySelector("#statusText")?.textContent || "";
    return /Loaded \d+ (data sources|component categories)/.test(s) || /failed/i.test(s);
  }, { timeout: 15_000 });
  await page.waitForTimeout(150);
}

test("?merged=1 routes the Log Inventory tab to the unified panel", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  // Click the Log Inventory tab (data-tab="inventory" — unchanged).
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const layout = await page.evaluate(() => ({
    legacyActive: document.querySelector("#tab-inventory")?.classList.contains("active") || false,
    mergedActive: document.querySelector("#tab-inventory-v2")?.classList.contains("active") || false,
    tabHighlight: document.querySelector('button.tab[data-tab="inventory"]')?.classList.contains("active") || false,
    subRegions: {
      filter: !!document.querySelector("#mergedInvFilter"),
      ignoreToggle: !!document.querySelector("#mergedInvIgnoreIncomplete"),
      diagram: !!document.querySelector("details#inventoryDiagram"),
      hierarchy: !!document.querySelector("#inventoryHierarchy"),
      analytics: !!document.querySelector("#inventoryAnalytics"),
      strategies: !!document.querySelector("#inventoryStrategies"),
      detectedTtps: !!document.querySelector("#detectedTtps"),
    },
  }));
  assert.equal(layout.tabHighlight, true, "Log Inventory tab button should be highlighted");
  assert.equal(layout.mergedActive, true, "merged panel #tab-inventory-v2 should be the visible one when flag is on");
  assert.equal(layout.legacyActive, false, "legacy #tab-inventory should not be active when merged flag is on");
  assert.deepEqual(layout.subRegions, {
    filter: true, ignoreToggle: true, diagram: true,
    hierarchy: true, analytics: true, strategies: true, detectedTtps: true,
  }, `every sub-region should exist, got ${JSON.stringify(layout.subRegions)}`);
});

test("without the flag, the legacy Log Inventory panel still activates", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page); // no ?merged=1
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const layout = await page.evaluate(() => ({
    legacyActive: document.querySelector("#tab-inventory")?.classList.contains("active") || false,
    mergedActive: document.querySelector("#tab-inventory-v2")?.classList.contains("active") || false,
    legacyTable: !!document.querySelector("#inventoryTable"),
  }));
  assert.equal(layout.legacyActive, true, "legacy #tab-inventory should be active without the flag");
  assert.equal(layout.mergedActive, false, "merged panel must not steal the route without the flag");
  assert.equal(layout.legacyTable, true, "legacy inventory table should render");
});

test("localStorage.MERGED_INVENTORY=1 enables the merged panel without the URL flag", async () => {
  const page = await newPage({ blockExternal: true });
  // Set the localStorage flag before the app boots so the state-init
  // reads it. Navigate to about:blank first so localStorage has an
  // origin to land on.
  await page.goto(`${ORIGIN}/`, { waitUntil: "domcontentloaded" });
  await page.evaluate(() => localStorage.setItem("MERGED_INVENTORY", "1"));
  await page.goto(`${ORIGIN}/`, { waitUntil: "networkidle" });
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const mergedActive = await page.evaluate(() => document.querySelector("#tab-inventory-v2")?.classList.contains("active"));
  assert.equal(mergedActive, true, "localStorage flag should activate the merged panel");
});
