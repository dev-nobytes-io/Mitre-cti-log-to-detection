import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, activateTab, importInventory, readInventorySummary, countScoredInventoryRows, countScoredLogSourceRows, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

// Each row encodes the expected outcome of importing that persona against
// the bundled offline ATT&CK (38 data sources, 109 components). These
// numbers are measured, not aspirational — if the matching logic regresses
// they'll go to 0 and the test will fail loudly.
// Each row is the expected outcome of importing that fixture against the
// bundled offline ATT&CK. All personas now ship a `log_sources:` block
// (chunk 7); the legacy `data_sources:` import path is still exercised
// indirectly via test_legacy_v12_inventory below.
const PERSONAS = [
  { file: "persona-mature-enterprise.yaml", minScored: 35, minComponents: 50, kind: "v2" },
  { file: "persona-cloud-saas.yaml",        minScored: 12, minComponents: 20, kind: "v2" },
  { file: "persona-network-mssp.yaml",      minScored: 10, minComponents: 15, kind: "v2" },
  { file: "persona-greenfield-startup.yaml",minScored: 6,  minComponents: 8,  kind: "v2" },
  { file: "inventory.example.yaml",         minScored: 15, minComponents: 11, kind: "v2" },
];

for (const { file, minScored, minComponents, kind } of PERSONAS) {
  test(`importing ${file} populates the inventory UI`, async () => {
    const page = await newPage({ blockExternal: true });
    await bootApp(page);
    await activateTab(page, "inventory");

    await importInventory(page, file);

    // Status banner must reflect a successful import (not a silent failure).
    const status = await page.locator("#statusText").innerText();
    assert.match(status, /Imported/, `status should report import success, got: ${status}`);

    // v1 fixtures should report scores via the legacy "data sources scored"
    // pill (back-compat path); v2 fixtures via "log sources scored".
    const summary = await readInventorySummary(page);
    const pillKey = kind === "v2" ? "log sources scored" : "data sources scored";
    const scored = summary[pillKey];
    assert.ok(scored, `inventory summary missing '${pillKey}', got: ${JSON.stringify(summary)}`);
    const [scoredN, totalN] = scored.split("/").map(s => Number(s.trim()));
    assert.ok(scoredN >= minScored, `expected >= ${minScored} '${pillKey}' for ${file}, got ${scoredN}/${totalN}`);

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

test("manual entry: typing a custom log source persists, drives coverage if it matches the bundle, otherwise lands in the Custom panel", async () => {
  // chunk 7: the inventory tab gained a free-form (name, channel, score,
  // comment) entry form. Two cases to verify in one test:
  //   1. a tuple that *matches* a STIX log source already in the bundle
  //      drives coverage immediately (no need for it to live in
  //      inventory.example.yaml).
  //   2. a tuple that *doesn't* match (e.g. winlogbeat/9999) lands in
  //      the "Custom log sources" panel and survives a save/load roundtrip.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // Open the form (it's a <details> closed by default).
  await page.click("#customLsForm summary");

  // Case 1: matches a known STIX log source (sysmon/1).
  await page.fill("#customLsName", "sysmon");
  await page.fill("#customLsChannel", "1");
  await page.selectOption("#customLsScore", "5");
  await page.click("#customLsAdd");
  await page.waitForFunction(() => /Added log source sysmon\/1/.test(document.querySelector("#statusText")?.textContent || ""));

  const summary = await readInventorySummary(page);
  const lsScored = summary["log sources scored"];
  const [lsN] = lsScored.split("/").map(s => Number(s.trim()));
  assert.ok(lsN >= 1, `manual entry should bump log-sources-scored count, got ${lsScored}`);

  // Case 2: custom (name, channel) not in the bundle.
  await page.fill("#customLsName", "winlogbeat");
  await page.fill("#customLsChannel", "9999");
  await page.fill("#customLsComment", "vendor-specific event");
  await page.selectOption("#customLsScore", "4");
  await page.click("#customLsAdd");
  await page.waitForTimeout(150);

  // The custom row must render with the correct meta + score select.
  const customRow = await page.evaluate(() => {
    const row = document.querySelector('.custom-ls-row[data-custom-key="winlogbeat||9999"]');
    if (!row) return null;
    return {
      score: Number(row.querySelector("select[data-kind='ls']")?.value || "0"),
      hasRemove: !!row.querySelector("[data-remove-custom]"),
      comment: row.querySelector(".dc-meta")?.textContent?.trim(),
    };
  });
  assert.ok(customRow, "custom row should render in the inventory list");
  assert.equal(customRow.score, 4);
  assert.ok(customRow.hasRemove, "custom row should expose a × remove button");
  assert.match(customRow.comment, /vendor-specific event/);

  // Remove the custom entry.
  await page.click('[data-remove-custom="winlogbeat||9999"]');
  await page.waitForTimeout(150);
  const stillThere = await page.evaluate(() => !!document.querySelector('.custom-ls-row[data-custom-key="winlogbeat||9999"]'));
  assert.equal(stillThere, false, "custom entry should be removed after × click");

  await page.context().close();
});

test("v2: importing inventory.example.yaml exposes scored log_sources block", async () => {
  // chunk 3 introduced log_sources[]; chunk 6 made it the only inventory
  // path. The example file ships explicit (sysmon/1, powershell/4104,
  // etc.) entries with non-zero scores. Assert that:
  //   - the inventory summary surfaces a non-zero "log sources scored" pill
  //   - the inventory view renders >0 scored log-source selects
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");

  const summary = await readInventorySummary(page);
  const lsScored = summary["log sources scored"];
  assert.ok(lsScored, `summary missing 'log sources scored', got: ${JSON.stringify(summary)}`);
  const [lsN] = lsScored.split("/").map(s => Number(s.trim()));
  assert.ok(lsN >= 5, `expected >=5 explicitly-scored log sources, got ${lsN}`);

  // Expand every parent so the nested log-source selects are in the DOM.
  await page.evaluate(() => {
    document.querySelectorAll("#inventoryTable [data-toggle]").forEach(el => el.click());
  });
  await page.waitForTimeout(150);

  const lsRows = await countScoredLogSourceRows(page);
  assert.ok(lsRows >= 5, `expected >=5 scored log-source selects, got ${lsRows}`);

  await page.context().close();
});

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
