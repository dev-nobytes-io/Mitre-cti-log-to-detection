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
import { newPage, bootApp, ORIGIN, SAMPLES_DIR, closeBrowser } from "../harness.mjs";

const SAMPLES = SAMPLES_DIR;

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

test("merged inventory: data-flow diagram renders on details-open + re-renders after a score change", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  // Cold start: <details> is closed so no SVG yet.
  const initial = await page.evaluate(() =>
    document.querySelectorAll("#inventoryDiagramHost svg").length);
  assert.equal(initial, 0, "diagram should not render while <details> is collapsed");

  // Open the diagram with no inventory yet — should show empty-state copy.
  await page.evaluate(() => { document.querySelector("#inventoryDiagram").open = true; document.querySelector("#inventoryDiagram").dispatchEvent(new Event("toggle")); });
  await page.waitForTimeout(400);
  const emptyState = await page.evaluate(() => document.querySelector("#inventoryDiagramHost")?.textContent || "");
  assert.match(emptyState, /Tick at least one channel/, `empty-state copy expected, got: ${emptyState.slice(0, 120)}`);

  // Pick a channel deterministically (analytic-driver, same shape as the
  // chunk-0 delta test) so we know scoring it produces a non-empty
  // diagram with downstream nodes.
  const target = await page.evaluate(async () => {
    const [{ loadOfflineBundle }] = await Promise.all([import("/js/attack.js")]);
    const attack = await loadOfflineBundle();
    for (const an of (attack.analytics || [])) {
      if ((an.logSourceIds || []).length < 1) continue;
      const ls = attack.logSourceById?.get(an.logSourceIds[0]);
      if (ls?.name && ls?.channel) return { name: ls.name, channel: ls.channel };
    }
    return null;
  });
  assert.ok(target, "couldn't resolve a target channel");

  // Score that channel via inventory APIs (skip the UI-expand dance —
  // chunk 3 already covers UI scoring; here we just need the diagram
  // re-render trigger).
  await page.evaluate(async ({ name, channel }) => {
    const inv = await import("/js/inventory.js");
    const cur = JSON.parse(localStorage.getItem("attack-inventory-v2") || "{}");
    const merged = inv.setLogSourceScore(cur, name, channel, 5);
    inv.setLogSourceEnabled(merged, name, channel, true);
    inv.saveInventory(merged);
    location.reload();
  }, target);
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);
  await page.evaluate(() => { document.querySelector("#inventoryDiagram").open = true; document.querySelector("#inventoryDiagram").dispatchEvent(new Event("toggle")); });
  // Wait for the debounced render + mermaid render.
  await page.waitForFunction(() => document.querySelectorAll("#inventoryDiagramHost svg").length > 0, { timeout: 5000 });
  const populated = await page.evaluate(() =>
    document.querySelectorAll("#inventoryDiagramHost svg").length);
  assert.ok(populated >= 1, `diagram should render an SVG once a channel is scored, got ${populated}`);
});

// Helpers for chunk 5: pick a multi-channel analytic deterministically
// so we can flip from "partial" (one channel scored) to "fullyMet"
// (all channels scored) and assert greying / toggle behaviour.
async function pickMultiChannelAnalytic(page) {
  return await page.evaluate(async () => {
    const [{ loadOfflineBundle }] = await Promise.all([import("/js/attack.js")]);
    const attack = await loadOfflineBundle();
    for (const an of (attack.analytics || [])) {
      if ((an.logSourceIds || []).length < 2) continue;
      const tuples = [];
      let ok = true;
      for (const id of an.logSourceIds) {
        const ls = attack.logSourceById?.get(id);
        if (!ls?.name || !ls?.channel) { ok = false; break; }
        tuples.push({ name: ls.name, channel: ls.channel });
      }
      if (!ok) continue;
      return { analyticName: an.name, tuples };
    }
    return null;
  });
}

async function scoreInventoryFromApi(page, tuples, score = 5) {
  await page.evaluate(async ({ tuples, score }) => {
    const inv = await import("/js/inventory.js");
    let cur = JSON.parse(localStorage.getItem("attack-inventory-v2") || "{}");
    for (const t of tuples) {
      cur = inv.setLogSourceScore(cur, t.name, t.channel, score);
      cur = inv.setLogSourceEnabled(cur, t.name, t.channel, true);
    }
    inv.saveInventory(cur);
  }, { tuples, score });
}

test("merged inventory: partial analytic appears greyed; full chain lights it up; toggle hides partials", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);

  const target = await pickMultiChannelAnalytic(page);
  assert.ok(target, "no multi-channel analytic in bundle");

  // Score only the first channel — analytic should be partial.
  await scoreInventoryFromApi(page, [target.tuples[0]], 5);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(200);

  const partialState = await page.evaluate(() => ({
    partial: document.querySelectorAll("#inventoryAnalytics .analytic-row.partial").length,
    lit: document.querySelectorAll("#inventoryAnalytics .analytic-row.lit").length,
  }));
  assert.ok(partialState.partial >= 1, `expected >=1 partial analytic, got ${partialState.partial}`);

  // Score every remaining channel of the analytic — it should flip to fullyMet.
  await scoreInventoryFromApi(page, target.tuples.slice(1), 5);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(200);

  const litState = await page.evaluate(() => ({
    partial: document.querySelectorAll("#inventoryAnalytics .analytic-row.partial").length,
    lit: document.querySelectorAll("#inventoryAnalytics .analytic-row.lit").length,
    activeStrategies: document.querySelectorAll("#inventoryStrategies .strategy-card.lit").length,
    detectedChips: document.querySelectorAll("#detectedTtps .ttp-chip").length,
  }));
  assert.ok(litState.lit >= 1, `expected >=1 lit analytic after scoring all channels, got ${litState.lit}`);
  assert.ok(litState.activeStrategies >= 1, `expected >=1 active strategy, got ${litState.activeStrategies}`);
  assert.ok(litState.detectedChips >= 1, `expected >=1 detected-TTP chip, got ${litState.detectedChips}`);
});

test("merged inventory: Ignore-incomplete toggle moves Coverage tab numbers (display + computation)", async () => {
  const page = await newPage({ blockExternal: true });
  await bootMerged(page);

  // Set up: import threats + score one channel of a multi-channel
  // analytic whose strategy detects a threat technique. With toggle
  // OFF (inclusive default), partial strategies should light + bump
  // the gaps-tab Covered count. Toggle ON should drop it back.
  await page.click('button.tab[data-tab="threats"]');
  await page.waitForTimeout(150);
  await page.setInputFiles("#groupsFile", `${SAMPLES}/threats-state-apts.yaml`);
  await page.waitForFunction(() => /Imported/.test(document.querySelector("#statusText")?.textContent || ""));
  await page.waitForTimeout(150);

  // Pick an analytic whose strategy detects a selected-threat technique.
  const target = await page.evaluate(async () => {
    const [{ loadOfflineBundle }, { selectedGroups }] = await Promise.all([
      import("/js/attack.js"), import("/js/threats.js"),
    ]);
    const attack = await loadOfflineBundle();
    const threats = JSON.parse(localStorage.getItem("attack-threats-v1") || "{}");
    const groups = selectedGroups(threats, attack);
    const threatTechIds = new Set();
    for (const g of groups) for (const t of (g.techniqueIds || [])) threatTechIds.add(t);
    const detectingStrats = (attack.detectionStrategies || []).filter(s =>
      (s.techniqueIds || []).some(t => threatTechIds.has(t)));
    for (const an of (attack.analytics || [])) {
      if ((an.logSourceIds || []).length < 2) continue;
      const inDetecting = detectingStrats.some(s => (s.analyticIds || []).includes(an.id));
      if (!inDetecting) continue;
      const tuples = [];
      let ok = true;
      for (const id of an.logSourceIds) {
        const ls = attack.logSourceById?.get(id);
        if (!ls?.name || !ls?.channel) { ok = false; break; }
        tuples.push({ name: ls.name, channel: ls.channel });
      }
      if (ok && tuples.length >= 2) return { tuples };
    }
    return null;
  });
  assert.ok(target, "couldn't find a multi-channel analytic that detects a threat technique");

  // Score ONLY the first channel — strategy is partial. Reload so the
  // in-page state.inventory picks up the new entry.
  await scoreInventoryFromApi(page, [target.tuples[0]], 5);
  await page.reload({ waitUntil: "networkidle" });
  await page.waitForFunction(() => /Loaded \d+ (data sources|component categories)/.test(document.querySelector("#statusText")?.textContent || ""));

  // Toggle starts OFF (inclusive). Read Coverage with partials counted.
  await page.click('button.tab[data-tab="gaps"]');
  await page.waitForTimeout(200);
  const inclusiveStats = await page.evaluate(() => {
    const out = {};
    for (const c of document.querySelectorAll("#threatStats .stat-card")) {
      out[c.querySelector(".label")?.textContent?.trim()] = Number(c.querySelector(".value")?.textContent?.trim() || "0");
    }
    return out;
  });

  // Flip the toggle ON via the merged inventory tab and re-read.
  await page.click('button.tab[data-tab="inventory"]');
  await page.waitForTimeout(150);
  await page.evaluate(() => {
    const cb = document.querySelector("#mergedInvIgnoreIncomplete");
    cb.checked = true;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page.waitForTimeout(200);
  await page.click('button.tab[data-tab="gaps"]');
  await page.waitForTimeout(200);
  const strictStats = await page.evaluate(() => {
    const out = {};
    for (const c of document.querySelectorAll("#threatStats .stat-card")) {
      out[c.querySelector(".label")?.textContent?.trim()] = Number(c.querySelector(".value")?.textContent?.trim() || "0");
    }
    return out;
  });

  const inclusiveCoverage = (inclusiveStats["Covered"] || 0) + (inclusiveStats["Partial"] || 0);
  const strictCoverage    = (strictStats["Covered"] || 0)    + (strictStats["Partial"] || 0);
  assert.ok(inclusiveCoverage >= strictCoverage,
    `inclusive (toggle OFF) coverage should be >= strict (toggle ON); got inclusive=${inclusiveCoverage} strict=${strictCoverage}`);
  // For the chosen partial-only setup, inclusive must move at least one
  // technique that strict doesn't.
  assert.ok(inclusiveCoverage > strictCoverage,
    `partial-only scoring should give inclusive coverage > strict; got inclusive=${inclusiveCoverage} strict=${strictCoverage}`);
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
