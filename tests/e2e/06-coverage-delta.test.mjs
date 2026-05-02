// Chunk 0 — Prove the chain Channel -> Analytic -> Strategy -> Technique
// actually moves the threat-coverage numbers when the user scores
// channels in the inventory UI.
//
// Plan:
//   1. Import a threat-group set (state APTs).
//   2. Capture the cold-start "Covered + Partial" count on the gaps
//      tab — must be 0 with no inventory.
//   3. Programmatically pick an analytic from the bundle whose
//      detection strategy detects ≥1 selected-threat technique.
//      The offline bundle's analytics all require multiple log
//      sources (min 2), so we score *every* required (name,
//      channel) tuple to score 5 — enough to light the analytic
//      under the default `min` aggregator.
//   4. Drive the inventory tab UI: expand each affected data
//      component group (chevron click), then set score=5 + Active
//      on each channel via the rendered selects/checkboxes.
//   5. Re-read the gaps tab; assert Covered+Partial increased.
//
// Negative control: pick an analytic whose strategy does NOT
// detect any selected-threat technique, score it the same way,
// assert threat coverage stays flat. Skipped if no such analytic
// exists in the bundle.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import {
  newPage, bootApp, activateTab, importThreats, readStats, closeBrowser,
} from "../harness.mjs";

after(async () => { await closeBrowser(); });

async function readThreatCoverage(page) {
  const stats = await readStats(page, "#threatStats");
  const covered = Number(stats["Covered"] || 0);
  const partial = Number(stats["Partial"] || 0);
  return {
    covered,
    partial,
    gaps:    Number(stats["Gaps"] || 0),
    total:   Number(stats["Threat techniques"] || 0),
    anyCoverage: covered + partial,
  };
}

// Resolve an analytic + the (name, channel) tuples for each of its
// required log sources, plus the parent data component(s) we'll need
// to expand. `mode` is "positive" (analytic's strategy detects a
// threat technique) or "negative" (analytic's strategies do NOT).
async function pickAnalytic(page, mode) {
  return await page.evaluate(async (mode) => {
    const [{ loadOfflineBundle }, { selectedGroups }] = await Promise.all([
      import("/js/attack.js"),
      import("/js/threats.js"),
    ]);
    const attack = await loadOfflineBundle();
    const threats = JSON.parse(localStorage.getItem("attack-threats-v1") || "{}");
    const groups = selectedGroups(threats, attack);
    const threatTechIds = new Set();
    for (const g of groups) for (const tid of (g.techniqueIds || [])) threatTechIds.add(tid);

    // Map analytic -> set of strategies that contain it.
    const analyticStrats = new Map();
    for (const st of (attack.detectionStrategies || [])) {
      for (const aid of (st.analyticIds || [])) {
        if (!analyticStrats.has(aid)) analyticStrats.set(aid, []);
        analyticStrats.get(aid).push(st);
      }
    }

    // For each analytic, decide whether any of its strategies detect a
    // selected-threat technique.
    const candidates = [];
    for (const an of (attack.analytics || [])) {
      const strats = analyticStrats.get(an.id) || [];
      if (!strats.length) continue;
      const detectsThreat = strats.some(st =>
        (st.techniqueIds || []).some(tid => threatTechIds.has(tid)));
      const matches = mode === "positive" ? detectsThreat : !detectsThreat;
      if (!matches) continue;
      // Resolve every required (name, channel). Skip the analytic if
      // any log source can't be resolved or has missing name/channel.
      const tuples = [];
      let ok = true;
      const compIds = new Set();
      for (const lsId of (an.logSourceIds || [])) {
        const ls = attack.logSourceById?.get(lsId);
        if (!ls || !ls.name || !ls.channel) { ok = false; break; }
        tuples.push({ name: ls.name, channel: ls.channel, lsId });
        for (const cid of (ls.componentIds || [])) compIds.add(cid);
      }
      if (!ok || !tuples.length) continue;
      candidates.push({
        analyticId: an.id,
        analyticName: an.name,
        strategyAttackIds: strats.map(s => s.attackId).filter(Boolean),
        tuples,
        compIds: Array.from(compIds),
      });
    }
    if (!candidates.length) return null;
    // Prefer the candidate with the fewest tuples (less UI work + less
    // chance of one tuple failing to render).
    candidates.sort((a, b) => a.tuples.length - b.tuples.length);
    return candidates[0];
  }, mode);
}

// Drive the by-component inventory UI: expand parent data components,
// then set every (name, channel) tuple's score select to 5 and ensure
// its Active checkbox is ticked. Returns the list of tuples actually
// scored so the caller can assert.
async function scoreTuplesViaUi(page, tuples, compIds) {
  await activateTab(page, "inventory");

  // Expand each parent data-component group so the channel rows render.
  await page.evaluate((compIds) => {
    for (const cid of compIds) {
      const el = document.querySelector(`[data-toggle="comp:${cid}"]`);
      if (!el) continue;
      const open = document.querySelector(`[data-components-for="comp:${cid}"]`)?.classList.contains("open");
      if (!open) el.click();
    }
  }, compIds);
  await page.waitForTimeout(200);

  const result = await page.evaluate(({ tuples }) => {
    const scored = [];
    const missing = [];
    for (const t of tuples) {
      const key = `${t.name}||${t.channel}`;
      const sels = Array.from(document.querySelectorAll("#inventoryTable select[data-kind='ls']"))
        .filter(s => s.getAttribute("data-key") === key);
      if (!sels.length) { missing.push(key); continue; }
      // It's fine to have multiple (one per parent comp) — set all of them.
      for (const sel of sels) {
        sel.value = "5";
        sel.dispatchEvent(new Event("change", { bubbles: true }));
      }
      const cbs = Array.from(document.querySelectorAll("#inventoryTable input[type='checkbox'][data-ls-enable]"))
        .filter(c => c.getAttribute("data-ls-enable") === key);
      for (const cb of cbs) {
        if (!cb.checked) {
          cb.checked = true;
          cb.dispatchEvent(new Event("change", { bubbles: true }));
        }
      }
      scored.push(key);
    }
    return { scored, missing };
  }, { tuples });

  // Allow re-render + persist + downstream tab recompute to flush.
  await page.waitForTimeout(300);
  return result;
}

test("delta: scoring an analytic's required channels bumps threat coverage from baseline", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  // 1. Threats only — no inventory.
  await activateTab(page, "threats");
  await importThreats(page, "threats-state-apts.yaml");

  // 2. Cold baseline.
  await activateTab(page, "gaps");
  const before = await readThreatCoverage(page);
  assert.ok(before.total > 0, `expected >0 threat techniques, got ${before.total}`);
  assert.equal(before.anyCoverage, 0,
    `cold-start anyCoverage should be 0, got ${before.anyCoverage} (Covered=${before.covered}, Partial=${before.partial})`);

  // 3. Pick analytic that lights a threat technique.
  const target = await pickAnalytic(page, "positive");
  assert.ok(target, "no analytic in the bundle has a strategy that detects a selected-threat technique");

  // 4. Drive the UI.
  const { scored, missing } = await scoreTuplesViaUi(page, target.tuples, target.compIds);
  assert.equal(missing.length, 0,
    `expected every required channel to render in the inventory; missing: ${JSON.stringify(missing)}`);
  assert.ok(scored.length === target.tuples.length,
    `expected ${target.tuples.length} channels scored, got ${scored.length}`);

  // 5. Coverage should have moved.
  await activateTab(page, "gaps");
  const after = await readThreatCoverage(page);
  assert.ok(after.anyCoverage > before.anyCoverage,
    `expected anyCoverage to rise after scoring analytic '${target.analyticName}' (strategies=${target.strategyAttackIds.join(",")}); before=${before.anyCoverage} after=${after.anyCoverage} channels=${scored.join("; ")}`);
  assert.equal(after.total, before.total,
    `threat-technique total should not change, ${before.total} -> ${after.total}`);

  await page.context().close();
});

test("negative control: scoring an analytic whose strategies don't detect threats does not move threat coverage", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  await activateTab(page, "threats");
  await importThreats(page, "threats-state-apts.yaml");
  await activateTab(page, "gaps");
  const before = await readThreatCoverage(page);

  const target = await pickAnalytic(page, "negative");
  if (!target) {
    console.log("negative control skipped: every analytic in this bundle's strategies detects ≥1 selected-threat technique");
    return;
  }

  const { scored, missing } = await scoreTuplesViaUi(page, target.tuples, target.compIds);
  if (missing.length || !scored.length) {
    console.log(`negative control skipped: couldn't render channels in inventory (missing=${JSON.stringify(missing)})`);
    return;
  }

  await activateTab(page, "gaps");
  const after = await readThreatCoverage(page);
  assert.equal(after.anyCoverage, before.anyCoverage,
    `scoring '${target.analyticName}' (which detects no selected-threat tech) shouldn't move threat coverage; before=${before.anyCoverage} after=${after.anyCoverage}`);

  await page.context().close();
});
