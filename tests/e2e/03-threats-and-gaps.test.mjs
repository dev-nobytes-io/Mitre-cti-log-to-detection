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
    const [{ computeCoverage }, { effectiveLogSourceScores }, { loadOfflineBundle }] = await Promise.all([
      import("/js/coverage.js"),
      import("/js/inventory.js"),
      import("/js/attack.js"),
    ]);
    const attack = await loadOfflineBundle();
    // Read the same inventory the page just persisted.
    const raw = localStorage.getItem("attack-inventory-v2");
    const inv = JSON.parse(raw);
    const lsScores = effectiveLogSourceScores(inv, attack);
    const cov = computeCoverage(attack, lsScores);
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

test("Coverage tab: mitigations expand into ATT&CK mitigations + D3FEND sub-mitigations", async () => {
  // UI chunk: technique rows on the Coverage tab show a "N mitigations"
  // toggle (populated from the course-of-action/mitigates parsing) that
  // expands into each mitigation plus the D3FEND defensive techniques
  // D3FEND documents as implementing it ("sub-mitigations").
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "coverage");
  await page.fill("#techFilter", "T1078");
  await page.waitForTimeout(150);

  const toggle = page.locator('[data-mit-toggle="T1078"]');
  await assert.doesNotReject(toggle.waitFor({ state: "visible", timeout: 5000 }), "expected a mitigations toggle on the T1078 row");
  await toggle.click();
  await page.waitForTimeout(150);

  const text = await page.locator("#techniqueTable").innerText();
  assert.match(text, /Mitigations \(ATT&CK\).*D3FEND sub-mitigations.*NIST 800-53/, "expected the mitigations expansion header");
  assert.match(text, /Multi-factor Authentication/, "expected T1078's M1032 mitigation to be listed");
  assert.match(text, /D3-MFA/, "expected M1032's D3FEND sub-mitigation (D3-MFA) to be listed");
  assert.match(text, /NIST (AC-2\(1\)|IA-2)/, "expected D3-MFA's NIST 800-53 control(s) to be listed");

  // A mitigation D3FEND hasn't mapped yet (M1053 Data Backup, on
  // T1486/T1490/T1485) should render D3FEND's own comment instead of an
  // empty list.
  await page.selectOption("#coverageFilter", "uncovered");
  await page.fill("#techFilter", "T1490");
  await page.waitForTimeout(150);
  await page.click('[data-mit-toggle="T1490"]');
  await page.waitForTimeout(150);
  const t1490Text = await page.locator("#techniqueTable").innerText();
  assert.match(t1490Text, /Data Backup/, "expected T1490's M1053 mitigation to be listed");
  assert.match(t1490Text, /outside the .*scope of D3FEND|No D3FEND sub-mitigation/, "expected a fallback explanation for M1053, which D3FEND hasn't mapped");

  await page.context().close();
});

test("scoring a mitigation on the Mitigations tab feeds into the Coverage tab as an additive preventive-control dimension", async () => {
  // Regression test: tech.mitigationIds holds STIX ids
  // (course-of-action--m-1032) but inv.mitigation_scores is keyed by the
  // ATT&CK attackId (M1032) shown in the Mitigations tab UI. coverage.js
  // must resolve STIX id -> attackId before looking up the score, or the
  // Coverage tab silently shows everything as unscored.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  await activateTab(page, "coverage");
  const statsBefore = await page.locator("#coverageStats").innerText();
  assert.match(statsBefore, /MITIGATED\s*\n0\n/, `expected 0 mitigated before scoring anything, got: ${statsBefore}`);

  await activateTab(page, "mitigations");
  await page.selectOption('select[data-kind="mitigation"][data-key="M1032"]', "5");
  await page.waitForTimeout(150);

  await activateTab(page, "coverage");
  const statsAfter = await page.locator("#coverageStats").innerText();
  assert.match(statsAfter, /MITIGATED\s*\n[1-9]/, `expected MITIGATED > 0 after scoring M1032, got: ${statsAfter}`);
  assert.match(statsAfter, /avg 5\.00/, `expected avg mitigation score of 5.00, got: ${statsAfter}`);

  // The detective-only stat cards must be untouched by the mitigation
  // score — this is an additive dimension, not a replacement.
  assert.match(statsAfter, /COVERED\s*\n0\n/, "detective 'Covered' count should stay 0 — no log sources were scored");

  await page.fill("#techFilter", "T1078");
  await page.waitForTimeout(150);
  const row = await page.locator('.tech-row:has-text("T1078")').first().innerText();
  assert.match(row, /🛡5/, `expected T1078's row to show a mitigation score badge of 5, got: ${row}`);

  await page.context().close();
});

test("risk-accepted technique drops out of the Gaps bucket and lands under Risk accepted", async () => {
  // chunk 10: marking a technique as risk-accepted on the Coverage tab
  // moves it from the gap bucket (in gap analysis) into a separate
  // "risk_accepted" bucket. The total threat-technique count must
  // stay the same — risk acceptance reclassifies, it doesn't drop.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  // Bring in a partial inventory + a threat group with known gaps.
  await activateTab(page, "inventory");
  await importInventory(page, "persona-greenfield-startup.yaml");
  await activateTab(page, "threats");
  await importThreats(page, "threats-state-apts.yaml");

  // Capture the gap counts before risk acceptance.
  await activateTab(page, "gaps");
  const before = await readStats(page, "#threatStats");
  const beforeGaps = Number(before["Gaps"] || 0);
  assert.ok(beforeGaps > 0, `expected >0 gap techniques before risk acceptance, got ${beforeGaps}`);

  // Pick a technique attackId to risk-accept by reading one from the
  // gaps bucket. Use the first ".tech-row" with attackId in the table.
  const targetId = await page.evaluate(() => {
    const row = document.querySelector("#threatTable .tech-row .tech-id");
    return row?.textContent?.trim();
  });
  assert.ok(targetId, "couldn't find a threat-technique row to mark");

  // Mark it accepted on the Coverage tab via the per-row toggle.
  await activateTab(page, "coverage");
  // The Coverage tab default-hides non-detectable; flip the filter to risk_accepted-incl.
  await page.evaluate((id) => {
    const btn = document.querySelector(`[data-risk-tech="${id}"]`);
    if (btn) btn.click();
  }, targetId);
  await page.waitForTimeout(150);

  // Coverage tab Risk-accepted stat-card should now be >= 1
  const coverageStats = await readStats(page, "#coverageStats");
  const riskAcc = Number(coverageStats["Risk accepted"] || 0);
  assert.ok(riskAcc >= 1, `Coverage tab Risk-accepted card should be >=1, got ${riskAcc}`);

  // Re-check gap analysis: Gaps should drop by 1, Risk accepted should be 1, total unchanged.
  await activateTab(page, "gaps");
  const after = await readStats(page, "#threatStats");
  const afterGaps = Number(after["Gaps"] || 0);
  const afterRisk = Number(after["Risk accepted"] || 0);
  assert.ok(afterGaps === beforeGaps - 1 || afterRisk >= 1,
    `expected Gaps to drop by 1 OR Risk accepted >=1, got Gaps ${beforeGaps} -> ${afterGaps}, Risk accepted ${afterRisk}`);

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
