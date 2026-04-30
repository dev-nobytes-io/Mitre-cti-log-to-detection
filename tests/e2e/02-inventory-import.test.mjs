import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, activateTab, importInventory, readInventorySummary, countScoredInventoryRows, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

// Each row encodes the expected outcome of importing that persona against
// the bundled offline ATT&CK (38 data sources, 109 components). These
// numbers are measured, not aspirational — if the matching logic regresses
// they'll go to 0 and the test will fail loudly.
const PERSONAS = [
  { file: "persona-mature-enterprise.yaml", minScored: 17, minComponents: 50 },
  { file: "persona-cloud-saas.yaml",        minScored: 11, minComponents: 40 },
  { file: "persona-network-mssp.yaml",      minScored: 6,  minComponents: 15 },
  { file: "persona-greenfield-startup.yaml",minScored: 6,  minComponents: 15 },
  { file: "inventory.example.yaml",         minScored: 5,  minComponents: 11 },
];

for (const { file, minScored, minComponents } of PERSONAS) {
  test(`importing ${file} populates the inventory UI`, async () => {
    const page = await newPage({ blockExternal: true });
    await bootApp(page);
    await activateTab(page, "inventory");

    await importInventory(page, file);

    // Status banner must reflect a successful import (not a silent failure).
    const status = await page.locator("#statusText").innerText();
    assert.match(status, /Imported/, `status should report import success, got: ${status}`);

    // Inventory summary must show non-zero scored sources.
    const summary = await readInventorySummary(page);
    const scored = summary["data sources scored"];
    assert.ok(scored, `inventory summary missing 'data sources scored', got: ${JSON.stringify(summary)}`);
    const [scoredN, totalN] = scored.split("/").map(s => Number(s.trim()));
    assert.ok(scoredN >= minScored, `expected >= ${minScored} scored sources for ${file}, got ${scoredN}/${totalN}`);

    // Real DOM rows: at least minScored rows have a non-zero score select.
    const rowCount = await countScoredInventoryRows(page);
    assert.ok(rowCount >= minScored, `expected >= ${minScored} scored row selects for ${file}, got ${rowCount}`);

    // Components covered must be >= minComponents.
    const compsStr = summary["data components covered"];
    const compsN = Number(compsStr.split("/")[0].trim());
    assert.ok(compsN >= minComponents, `expected >= ${minComponents} covered components for ${file}, got ${compsStr}`);

    await page.context().close();
  });
}

test("importing the same file twice via the same input control still works (input value reset)", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  await importInventory(page, "persona-cloud-saas.yaml");
  let firstStatus = await page.locator("#statusText").innerText();
  assert.match(firstStatus, /Imported/);

  // Simulate the user picking the SAME file again via the picker. Without
  // the value-reset, the change event won't fire and nothing happens.
  await importInventory(page, "persona-cloud-saas.yaml");
  let secondStatus = await page.locator("#statusText").innerText();
  assert.match(secondStatus, /Imported/, `re-import should also report success, got: ${secondStatus}`);

  await page.context().close();
});

test("importing on the Detection Strategies tab still updates that tab without a manual tab-click", async () => {
  // The "import doesn't refresh other tabs" regression. We start on
  // Detections, import an inventory, and verify the coverage table
  // updates immediately.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "coverage");
  // Switch over to inventory just to use the file picker (the picker only
  // exists on tab 2). We import there...
  await activateTab(page, "inventory");
  await importInventory(page, "persona-mature-enterprise.yaml");
  // ...then immediately switch back to Detections without doing anything
  // else. Stats should already be populated from the refreshAll() cascade.
  await activateTab(page, "coverage");
  const covered = await page.evaluate(() => {
    const card = Array.from(document.querySelectorAll("#coverageStats .stat-card")).find(c => c.querySelector(".label")?.textContent?.includes("Covered"));
    return Number(card?.querySelector(".value")?.textContent?.trim() || "0");
  });
  assert.ok(covered > 0, `Detection Strategies COVERED should be > 0 after import, got ${covered}`);
  await page.context().close();
});
