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

test("merged inventory: 3-level hierarchy expands Data Component → Log Source → Channel", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  // Top level (Data Component) rows present, collapsed.
  const compCount = await page.evaluate(() =>
    document.querySelectorAll("#inventoryHierarchy [data-merged-comp]").length);
  assert.ok(compCount >= 5, `expected >=5 data-component rows, got ${compCount}`);

  // Expand the first component, then expand its first log-source name,
  // assert at least one channel row + score select appears.
  const expansion = await page.evaluate(() => {
    const compToggle = document.querySelector("#inventoryHierarchy [data-merged-comp] [data-merged-toggle]");
    if (!compToggle) return { ok: false, reason: "no comp toggle" };
    compToggle.click();
    return { ok: true };
  });
  assert.ok(expansion.ok, `comp expand failed: ${expansion.reason}`);
  await page.waitForTimeout(120);

  const drilled = await page.evaluate(() => {
    const nameToggle = document.querySelector("#inventoryHierarchy [data-merged-name] [data-merged-toggle]");
    if (!nameToggle) return { ok: false, reason: "no log-source-name toggle after comp expand" };
    nameToggle.click();
    return { ok: true };
  });
  assert.ok(drilled.ok, `name expand failed: ${drilled.reason}`);
  await page.waitForTimeout(120);

  const leaf = await page.evaluate(() => {
    const channelRows = document.querySelectorAll("#inventoryHierarchy [data-merged-channel]");
    const scoreSelects = document.querySelectorAll("#inventoryHierarchy select[data-kind='merged-ls']");
    const activeBoxes = document.querySelectorAll("#inventoryHierarchy input[data-merged-active]");
    return { channels: channelRows.length, scores: scoreSelects.length, actives: activeBoxes.length };
  });
  assert.ok(leaf.channels >= 1, `expected >=1 channel row after expand, got ${leaf.channels}`);
  assert.equal(leaf.channels, leaf.scores, "every channel row should expose a score select");
  assert.equal(leaf.channels, leaf.actives, "every channel row should expose an Active checkbox");
});

test("merged inventory: scoring + active state persists to localStorage", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  // Expand the first comp + first name to surface a channel row.
  await page.evaluate(() => {
    document.querySelector("#inventoryHierarchy [data-merged-comp] [data-merged-toggle]")?.click();
  });
  await page.waitForTimeout(120);
  await page.evaluate(() => {
    document.querySelector("#inventoryHierarchy [data-merged-name] [data-merged-toggle]")?.click();
  });
  await page.waitForTimeout(120);

  // Pick the first channel: tick Active + score 5.
  const channelKey = await page.evaluate(() => {
    const cb = document.querySelector("#inventoryHierarchy input[data-merged-active]");
    const sel = document.querySelector("#inventoryHierarchy select[data-kind='merged-ls']");
    if (!cb || !sel) return null;
    if (!cb.checked) { cb.checked = true; cb.dispatchEvent(new Event("change", { bubbles: true })); }
    sel.value = "5";
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    return cb.getAttribute("data-merged-active");
  });
  assert.ok(channelKey, "couldn't find a channel row to score");
  await page.waitForTimeout(200);

  // Reload and re-open merged panel — state should survive.
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const persisted = await page.evaluate((key) => {
    const inv = JSON.parse(localStorage.getItem("attack-inventory-v2") || "{}");
    const [name, channel] = key.split("||");
    const entry = (inv.log_sources || []).find(e =>
      (e.name || "").toLowerCase() === name.toLowerCase() &&
      (e.channel || "").toLowerCase() === channel.toLowerCase());
    return entry && { score: entry.score, enabled: entry.enabled };
  }, channelKey);
  assert.ok(persisted, `entry for ${channelKey} should persist`);
  assert.equal(persisted.score, 5, `score should persist as 5, got ${persisted.score}`);
  assert.equal(persisted.enabled, true, "enabled flag should persist as true");
});

test("merged inventory: filter narrows visible components and force-expands matches", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const totalComps = await page.evaluate(() =>
    document.querySelectorAll("#inventoryHierarchy [data-merged-comp]").length);

  // Type "process" — the bundle has Process Creation, Process Termination, etc.
  await page.fill("#mergedInvFilter", "process");
  await page.waitForTimeout(150);

  const filtered = await page.evaluate(() => ({
    comps: document.querySelectorAll("#inventoryHierarchy [data-merged-comp]").length,
    channels: document.querySelectorAll("#inventoryHierarchy [data-merged-channel]").length,
  }));
  assert.ok(filtered.comps < totalComps, `filter should narrow components from ${totalComps}, got ${filtered.comps}`);
  assert.ok(filtered.channels >= 1, `filter should force-expand and show channel rows, got ${filtered.channels}`);
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
