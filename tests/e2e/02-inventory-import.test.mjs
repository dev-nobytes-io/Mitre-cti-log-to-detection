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

test("manual entry: typing a custom log source persists, drives coverage if it matches the bundle, otherwise lands in the right group", async () => {
  // chunk 7 + chunk 9: the inventory tab gained a free-form
  // (name, channel, score, comment) entry form at the top, and a
  // by-name grouping (default). Two cases to verify in one test:
  //   1. a tuple that *matches* a STIX log source already in the
  //      bundle (sysmon/1) drives coverage immediately.
  //   2. a tuple that *doesn't* match (winlogbeat/9999) lands in its
  //      own by-name group and exposes a × remove button.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // chunk 18: picker is the default view; switch to by-name so the
  // existing winlogbeat-group assertions still locate their target.
  await page.click('input[name="inventoryGrouping"][value="name"]');
  await page.waitForTimeout(120);

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

  // The custom entry should land in the "winlogbeat" group with a (custom) marker.
  // Expand the group first.
  await page.evaluate(() => document.querySelector('[data-toggle="name:winlogbeat"]')?.click());
  await page.waitForTimeout(150);

  const customRow = await page.evaluate(() => {
    const wrap = document.querySelector('[data-components-for="name:winlogbeat"]');
    const row = wrap?.querySelector(".dc-row.by-name-row");
    if (!row) return null;
    return {
      score: Number(row.querySelector("select[data-kind='ls']")?.value || "0"),
      hasRemove: !!row.querySelector("[data-remove-custom]"),
      isCustom: /\(custom\)/.test(row.textContent || ""),
      comment: row.textContent || "",
    };
  });
  assert.ok(customRow, "custom row should render in the winlogbeat group");
  assert.equal(customRow.score, 4);
  assert.ok(customRow.hasRemove, "custom row should expose a × remove button");
  assert.ok(customRow.isCustom, "row should be marked (custom) since the bundle doesn't know winlogbeat/9999");
  assert.match(customRow.comment, /vendor-specific event/);

  // Remove the custom entry.
  await page.click('[data-remove-custom="winlogbeat||9999"]');
  await page.waitForTimeout(150);
  const stillThere = await page.evaluate(() => !!document.querySelector('[data-toggle="name:winlogbeat"]'));
  assert.equal(stillThere, false, "winlogbeat group should disappear after the only entry is removed");

  await page.context().close();
});

test("manual entry → component map: a custom log source mapped to a component drives that component's score (chunk 13)", async () => {
  // chunk 13: when a user adds a custom (name, channel) tuple that the
  // bundle doesn't know about (e.g. winlogbeat/9999), they can tick
  // data components that the feed actually observes. Scoring then
  // projects onto those components. Without the picker, the score had
  // no upstream effect.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // Open the manual-entry form and the nested component-map dropdown.
  await page.click("#customLsForm summary");
  await page.click(".component-map-form > summary");

  // Find the first component checkbox and capture which component it represents.
  const target = await page.evaluate(() => {
    const box = document.querySelector("#customLsCompPicker input[data-comp-pick]");
    if (!box) return null;
    box.checked = true;
    box.dispatchEvent(new Event("change", { bubbles: true }));
    const label = box.closest("label")?.textContent?.trim().split("/")[0].trim();
    return { compId: box.getAttribute("data-comp-pick"), label };
  });
  assert.ok(target, "component picker should expose at least one checkbox");

  // Capture the component's current effective score on the Components tab.
  await activateTab(page, "components");
  const before = await page.evaluate((compId) => {
    const row = document.querySelector(`#componentTable [data-comp-id="${compId}"]`);
    return Number(row?.querySelector(".score-badge")?.textContent || "0");
  }, target.compId);

  // Add the custom tuple with a high score.
  await activateTab(page, "inventory");
  await page.fill("#customLsName", "winlogbeat");
  await page.fill("#customLsChannel", "9999");
  await page.selectOption("#customLsScore", "5");
  await page.fill("#customLsComment", "vendor feed for component-X");
  await page.click("#customLsAdd");
  await page.waitForFunction(() => /Added log source winlogbeat\/9999.*mapped to 1 component/.test(document.querySelector("#statusText")?.textContent || ""));

  // Confirm: the component the user mapped now has score 5 (from the projected custom log source).
  await activateTab(page, "components");
  const after = await page.evaluate((compId) => {
    const row = document.querySelector(`#componentTable [data-comp-id="${compId}"]`);
    return Number(row?.querySelector(".score-badge")?.textContent || "0");
  }, target.compId);
  assert.equal(after, Math.max(before, 5), `mapped component should pick up the projected score; before=${before}, after=${after}`);

  await page.context().close();
});

test("Inventory picker view + activation strip + bulk enable (chunk 18)", async () => {
  // chunk 18: the Log Inventory tab now opens on the picker view by
  // default (flat list, one row per channel, with bulk enable). The
  // activation strip shows live cascade counts. After ticking one
  // row, the strip should bump from 0 → 1 enabled and at least one
  // component should activate.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  const defaults = await page.evaluate(() => ({
    pickerActive: document.querySelector('input[name="inventoryGrouping"][value="picker"]')?.checked,
    pickerControlsVisible: !document.querySelector("#inventoryPickerControls")?.hidden,
    stripExists: !!document.querySelector("#inventoryActivationStrip"),
  }));
  assert.equal(defaults.pickerActive, true, "default grouping should be 'picker'");
  assert.equal(defaults.pickerControlsVisible, true, "picker controls (filter + bulk buttons) should be visible");
  assert.equal(defaults.stripExists, true, "activation strip container should exist");

  // Strip baseline (no inventory imported, fresh load — though
  // chunk 16 may have left some localStorage from prior tests; assert
  // we read the cells without crashing).
  const baseline = await page.evaluate(() => ({
    cells: Array.from(document.querySelectorAll("#inventoryActivationStrip .strip-cell strong")).map(s => Number(s.textContent || "0")),
  }));
  assert.equal(baseline.cells.length, 4, `expected 4 strip cells, got ${baseline.cells.length}`);

  // Enable the first picker row + score it 5; the score select
  // appears AFTER the enable checkbox is ticked because the row
  // re-renders, so we have to re-query.
  const targetKey = await page.evaluate(() => {
    const cb = document.querySelector('#inventoryTable input[data-pick-enable]');
    if (!cb) return null;
    cb.checked = true;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
    return cb.dataset.pickEnable;
  });
  assert.ok(targetKey, "picker should expose at least one enable checkbox");
  await page.waitForTimeout(150);

  await page.evaluate((key) => {
    const sel = document.querySelector(`#inventoryTable select[data-kind='ls'][data-key="${key}"]`);
    if (sel) { sel.value = "5"; sel.dispatchEvent(new Event("change", { bubbles: true })); }
  }, targetKey);
  await page.waitForTimeout(150);

  const after = await page.evaluate(() => ({
    cells: Array.from(document.querySelectorAll("#inventoryActivationStrip .strip-cell strong")).map(s => Number(s.textContent || "0")),
    pickerCount: document.querySelector("#invPickerCount")?.textContent || "",
  }));
  // At least one log source enabled, at least one component activated.
  assert.ok(after.cells[0] >= 1, `expected log-sources-enabled to be >=1 after toggle + score, got ${after.cells[0]}`);
  assert.ok(after.cells[1] >= 1, `expected components-activated to be >=1, got ${after.cells[1]}`);
  assert.match(after.pickerCount, /\d+ enabled/, `picker count chip should report enabled count, got: ${after.pickerCount}`);

  await page.context().close();
});

test("Data Components tab highlights covered rows + expansion lists log sources feeding each component", async () => {
  // chunk 12: visible bug repro — after importing inventory.example.yaml,
  // the Components tab must (a) colour-code rows by score (covered/
  // partial/uncovered border-left tints), (b) tag each row with a
  // "scored" / "uncovered" pill, (c) expand on chevron click to show
  // which log sources feed the component and which analytics reference
  // it.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");
  await activateTab(page, "components");
  await page.waitForTimeout(150);

  const counts = await page.evaluate(() => ({
    covered: document.querySelectorAll("#componentTable .tech-row.comp-covered").length,
    partial: document.querySelectorAll("#componentTable .tech-row.comp-partial").length,
    uncovered: document.querySelectorAll("#componentTable .tech-row.comp-uncovered").length,
    scoredTags: document.querySelectorAll("#componentTable .cov-tag").length,
    uncTags: document.querySelectorAll("#componentTable .unc-tag").length,
  }));
  assert.ok(counts.covered + counts.partial >= 5, `expected >=5 visibly-covered/partial component rows after importing the example, got covered=${counts.covered} partial=${counts.partial}`);
  assert.ok(counts.scoredTags >= 5, `expected >=5 'scored' pills, got ${counts.scoredTags}`);

  // Click the first scored row's chevron — expansion should render
  // log-source feed list with .ls-on dots when scored.
  const expanded = await page.evaluate(() => {
    const toggle = document.querySelector("#componentTable .tech-row.comp-covered .comp-toggle");
    if (!toggle) return null;
    toggle.click();
    return true;
  });
  assert.ok(expanded, "expected at least one covered row with a clickable chevron");
  await page.waitForTimeout(150);

  const expansion = await page.evaluate(() => {
    const exp = document.querySelector("#componentTable .comp-expansion");
    if (!exp) return null;
    return {
      hasLsRows: exp.querySelectorAll(".comp-ls-row").length,
      lsOnCount: exp.querySelectorAll(".comp-ls-row.ls-on").length,
      hasAnRows: exp.querySelectorAll(".comp-an-row").length,
      sectionHeaders: Array.from(exp.querySelectorAll(".comp-section-h")).map(h => h.textContent),
    };
  });
  assert.ok(expansion, "expansion block should appear after clicking a chevron");
  assert.ok(expansion.hasLsRows >= 1, `expansion should list >=1 log source, got ${expansion.hasLsRows}`);
  assert.ok(expansion.lsOnCount >= 1, `at least one log source under a covered component should be lit (.ls-on), got ${expansion.lsOnCount}`);
  assert.ok(expansion.sectionHeaders.some(h => /Log sources feeding/i.test(h)), `expected 'Log sources feeding' section header, got: ${JSON.stringify(expansion.sectionHeaders)}`);

  await page.context().close();
});

test("by-name view: groups every channel under its log-source name and the enable toggle parks coverage", async () => {
  // chunk 9: the inventory tab gained a "Group by: log source name /
  // data component" toggle. By-name is the new default. Asserts:
  //   - importing the example inventory groups all sysmon/* channels
  //     under one expandable banner,
  //   - the banner footer shows "+ Add channel under sysmon",
  //   - flipping one row's "enabled" checkbox to off drops the
  //     "log sources scored" pill by 1.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");
  await page.waitForTimeout(150);

  // chunk 18: switch to the by-name view (picker is now the default).
  await page.click('input[name="inventoryGrouping"][value="name"]');
  await page.waitForTimeout(120);
  const grouping = await page.evaluate(() => document.querySelector('input[name="inventoryGrouping"][value="name"]')?.checked);
  assert.equal(grouping, true, "by-name grouping should be active after click");

  // Expand the sysmon banner.
  await page.evaluate(() => {
    const t = document.querySelector('[data-toggle="name:sysmon"]');
    if (t) t.click();
  });
  await page.waitForTimeout(150);

  const sysmonRows = await page.evaluate(() => {
    const wrap = document.querySelector('[data-components-for="name:sysmon"]');
    return Array.from(wrap?.querySelectorAll(".dc-row.by-name-row") || []).length;
  });
  assert.ok(sysmonRows >= 5, `expected >=5 sysmon channel rows, got ${sysmonRows}`);

  const formExists = await page.evaluate(() => !!document.querySelector('form.add-channel-form[data-add-channel-name="sysmon"]'));
  assert.ok(formExists, "Add channel form should appear under the sysmon group");

  // Read scored count, flip one row off, read scored count again.
  const beforeScored = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll("#inventorySummary .pill")).find(p => /log sources scored/.test(p.textContent));
    return Number(el?.querySelector("strong")?.textContent.split("/")[0].trim() || "0");
  });
  assert.ok(beforeScored >= 5, `expected >=5 log sources scored before park, got ${beforeScored}`);

  // Disable sysmon/1 by toggling its enable checkbox.
  await page.evaluate(() => {
    const cb = document.querySelector('input[type=checkbox][data-ls-enable="sysmon||1"]');
    if (cb) { cb.checked = false; cb.dispatchEvent(new Event("change", { bubbles: true })); }
  });
  await page.waitForTimeout(150);

  const afterScored = await page.evaluate(() => {
    const el = Array.from(document.querySelectorAll("#inventorySummary .pill")).find(p => /log sources scored/.test(p.textContent));
    return Number(el?.querySelector("strong")?.textContent.split("/")[0].trim() || "0");
  });
  assert.equal(afterScored, beforeScored - 1, `disabling sysmon/1 should drop scored count by exactly 1, got ${beforeScored} -> ${afterScored}`);

  await page.context().close();
});

test("by-name view: + Add channel inline form scores a new event code under the existing name", async () => {
  // chunk 9: the per-name footer "+ Add channel" form must accept a
  // new event code, save the score, and merge it into the same name
  // group (so the user doesn't end up with a custom-only entry when
  // the channel matches a known bundle log source).
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  // chunk 18: switch to by-name; picker is now default.
  await page.click('input[name="inventoryGrouping"][value="name"]');
  await page.waitForTimeout(120);

  // Expand the sysmon group (will be empty of saved entries on a fresh load).
  await page.evaluate(() => document.querySelector('[data-toggle="name:sysmon"]')?.click());
  await page.waitForTimeout(150);

  // Use the inline Add-channel form with channel 5 (Process Termination, in the bundle).
  await page.evaluate(() => {
    const form = document.querySelector('form.add-channel-form[data-add-channel-name="sysmon"]');
    form.querySelector("[data-add-channel-channel]").value = "5";
    form.querySelector("[data-add-channel-score]").value = "4";
    form.querySelector("[data-add-channel-comment]").value = "Process Termination";
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await page.waitForTimeout(200);

  const status = await page.locator("#statusText").innerText();
  assert.match(status, /Added sysmon\/5/, `status should report add, got: ${status}`);

  // The new row must be visible inside the same sysmon group, with the
  // score select reflecting 4 and no "(custom)" label (sysmon/5 is in
  // the bundle).
  const newRow = await page.evaluate(() => {
    const wrap = document.querySelector('[data-components-for="name:sysmon"]');
    const row = Array.from(wrap?.querySelectorAll(".dc-row.by-name-row") || []).find(r => /^5/.test((r.querySelector(".dc-name")?.textContent || "").trim()));
    if (!row) return null;
    return {
      score: Number(row.querySelector("select[data-kind='ls']")?.value || "0"),
      isCustom: /\(custom\)/.test(row.textContent || ""),
    };
  });
  assert.ok(newRow, "newly-added sysmon/5 row should render in the sysmon group");
  assert.equal(newRow.score, 4);
  assert.equal(newRow.isCustom, false, "channel 5 is in the bundle so the row must NOT be marked (custom)");

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

  // chunk 18: picker is the default view; switch to by-name so the
  // nested-toggle expansion logic this test relies on still works.
  await page.click('input[name="inventoryGrouping"][value="name"]');
  await page.waitForTimeout(120);

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
