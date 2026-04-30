import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, activateTab, importInventory, importThreats, readStats, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

const THREAT_SAMPLES = [
  { file: "threats.example.yaml",     minSelected: 4 },
  { file: "threats-ransomware.yaml",  minSelected: 3 },  // Wizard Spider, FIN7, Carbanak, Scattered Spider, INDRIK SPIDER, Earth Lusca, Ember Bear, Chimera = 8 listed; offline bundle has 7 of these
  { file: "threats-state-apts.yaml",  minSelected: 7 },  // 9 listed in YAML; offline bundle has 8
  { file: "threats-financial.yaml",   minSelected: 5 },  // 8 listed; offline has 6
];

for (const { file, minSelected } of THREAT_SAMPLES) {
  test(`importing ${file} selects groups in the picker`, async () => {
    const page = await newPage({ blockExternal: true });
    await bootApp(page);
    await activateTab(page, "threats");
    await importThreats(page, file);

    const status = await page.locator("#statusText").innerText();
    assert.match(status, /Imported/, `status should report group import, got: ${status}`);

    // Count selected rows in the group list.
    const selected = await page.evaluate(() =>
      document.querySelectorAll("#groupList .group-row.selected input[type=checkbox]:checked").length
    );
    assert.ok(selected >= minSelected, `expected >= ${minSelected} selected groups for ${file}, got ${selected}`);

    await page.context().close();
  });
}

test("v2 coverage: importing inventory.example.yaml lights up at least one technique via the strategy chain", async () => {
  // chunk 4: scoring log sources should flow Log Source -> Analytic ->
  // Strategy -> Technique. The example inventory scores sysmon/1,
  // powershell/4104, windows-security/4624 etc. -- each of which is
  // referenced by an analytic in the offline bundle. At least one
  // technique should land with weightedScore > 0 and the engine should
  // report 'v2'.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");
  await activateTab(page, "coverage");

  const result = await page.evaluate(async () => {
    const [{ computeCoverageV2 }, { effectiveLogSourceScores }, { loadOfflineBundle }] = await Promise.all([
      import("/js/coverage.js"),
      import("/js/inventory.js"),
      import("/js/attack.js"),
    ]);
    const attack = await loadOfflineBundle();
    // Read the same inventory the page just persisted.
    const raw = localStorage.getItem("attack-inventory-v2");
    const inv = JSON.parse(raw);
    const lsScores = effectiveLogSourceScores(inv, attack);
    const cov = computeCoverageV2(attack, lsScores);
    const lit = cov.rows.filter(r => r.weightedScore > 0);
    return {
      engine: cov.engine,
      total: cov.summary.total,
      covered: cov.summary.covered,
      sample: lit.slice(0, 3).map(r => ({ id: r.attackId, score: r.weightedScore, lit: r.litStrategies, total: r.totalStrategies })),
    };
  });

  assert.equal(result.engine, "v2", "expected v2 engine to be active");
  assert.ok(result.covered > 0, `expected >0 covered techniques via the v2 chain, got ${result.covered}`);
  assert.ok(result.sample.length > 0, `expected at least one lit technique, got ${JSON.stringify(result)}`);

  // Coverage tab card "Covered" must reflect the v2 result.
  const coveredCard = await page.evaluate(() => {
    const card = Array.from(document.querySelectorAll("#coverageStats .stat-card")).find(c => c.querySelector(".label")?.textContent?.includes("Covered"));
    return Number(card?.querySelector(".value")?.textContent || "0");
  });
  assert.ok(coveredCard > 0, `expected Coverage tab Covered card to be > 0, got ${coveredCard}`);

  await page.context().close();
});

test("gap analysis populates when both inventory and threats are imported", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  await activateTab(page, "inventory");
  await importInventory(page, "persona-greenfield-startup.yaml");

  await activateTab(page, "threats");
  await importThreats(page, "threats-state-apts.yaml");

  await activateTab(page, "gaps");
  const stats = await readStats(page, "#threatStats");

  // Stat-card labels are written in title case in the DOM (CSS uppercases
  // them at display time); textContent preserves the original case.
  assert.ok(stats["Selected groups"], `expected 'Selected groups' card on gaps tab, got: ${JSON.stringify(stats)}`);
  const selectedN = Number(stats["Selected groups"]);
  assert.ok(selectedN >= 7, `expected >= 7 selected groups, got ${selectedN}`);

  const totalN = Number(stats["Threat techniques"]);
  assert.ok(totalN > 0, `expected > 0 threat techniques, got ${totalN}`);

  const gaps = Number(stats["Gaps"]);
  const covered = Number(stats["Covered"]);
  const partial = Number(stats["Partial"]);
  const undet = Number(stats["Undetectable"]);
  assert.equal(covered + gaps + partial + undet, totalN,
    `categories should sum to total, got covered=${covered} partial=${partial} gaps=${gaps} undet=${undet} total=${totalN}`);

  // The threat-technique table should render rows.
  const rowCount = await page.evaluate(() => document.querySelectorAll("#threatTable .tech-row:not(.header)").length);
  assert.ok(rowCount > 0, `expected threat-technique rows, got ${rowCount}`);

  await page.context().close();
});
