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
