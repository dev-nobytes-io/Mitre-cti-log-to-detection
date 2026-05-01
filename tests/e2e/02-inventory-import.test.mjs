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

  // The custom entry should land in the dedicated "Custom log sources"
  // block at the top of the by-component view (chunk N restructured the
  // inventory tab to a Data Component → Log Source → Channel hierarchy;
  // custom tuples have no parent component so they get their own block).
  const customRow = await page.evaluate(() => {
    const row = document.querySelector('.dc-row.custom-ls-row[data-custom-key="winlogbeat||9999"]');
    if (!row) return null;
    return {
      score: Number(row.querySelector("select[data-kind='ls']")?.value || "0"),
      hasRemove: !!row.querySelector("[data-remove-custom]"),
      isCustom: /\(custom\)/.test(row.textContent || ""),
      comment: row.textContent || "",
    };
  });
  assert.ok(customRow, "custom row should render in the Custom log sources block");
  assert.equal(customRow.score, 4);
  assert.ok(customRow.hasRemove, "custom row should expose a × remove button");
  assert.ok(customRow.isCustom, "row should be marked (custom) since the bundle doesn't know winlogbeat/9999");
  assert.match(customRow.comment, /vendor-specific event/);

  // Remove the custom entry.
  await page.click('[data-remove-custom="winlogbeat||9999"]');
  await page.waitForTimeout(150);
  const stillThere = await page.evaluate(() => !!document.querySelector('.dc-row.custom-ls-row[data-custom-key="winlogbeat||9999"]'));
  assert.equal(stillThere, false, "custom row should disappear after × remove");

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
  // chunk 18 (adapted): the picker is opt-in via a 3rd radio
  // (component-view stays default to preserve the present DC -> LS ->
  // Channel hierarchy workflow). Activation strip lives above the
  // table on every grouping and shows the live cascade. Switching to
  // picker shows the bulk controls + flat-list rows; ticking + scoring
  // one row should bump the strip's log-sources-enabled and
  // components-activated cells.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // Activation strip should be present regardless of grouping.
  const stripCells = await page.evaluate(() => Array.from(document.querySelectorAll("#inventoryActivationStrip .strip-cell strong")).length);
  assert.equal(stripCells, 4, `expected 4 activation-strip cells, got ${stripCells}`);

  // Picker controls hidden by default (component view is the default).
  const pickerHiddenAtBoot = await page.evaluate(() => document.querySelector("#inventoryPickerControls")?.hidden);
  assert.equal(pickerHiddenAtBoot, true, "picker controls should be hidden when component view is active");

  // Switch to picker via the 3rd radio.
  await page.click('input[name="inventoryGrouping"][value="picker"]');
  await page.waitForTimeout(150);

  const pickerVisible = await page.evaluate(() => ({
    controlsVisible: !document.querySelector("#inventoryPickerControls")?.hidden,
    pickerRowCount: document.querySelectorAll("#inventoryTable .picker-row").length,
  }));
  assert.equal(pickerVisible.controlsVisible, true, "picker controls should appear when picker is selected");
  assert.ok(pickerVisible.pickerRowCount >= 2, `expected >=2 picker rows (header + 1+ entry), got ${pickerVisible.pickerRowCount}`);

  // Reset inventory so the strip starts at 0 enabled.
  await page.click("#resetInventoryBtn");
  await page.waitForTimeout(150);

  // Tick the first picker row to enable it.
  const targetKey = await page.evaluate(() => {
    const cb = document.querySelector('#inventoryTable input[data-pick-enable]');
    if (!cb) return null;
    cb.checked = true;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
    return cb.dataset.pickEnable;
  });
  assert.ok(targetKey, "picker should expose at least one enable checkbox");
  await page.waitForTimeout(150);

  // Score it 5 (the score select only appears once enabled, so re-query).
  await page.evaluate((key) => {
    const sel = document.querySelector(`#inventoryTable select[data-kind='ls'][data-key="${key}"]`);
    if (sel) { sel.value = "5"; sel.dispatchEvent(new Event("change", { bubbles: true })); }
  }, targetKey);
  await page.waitForTimeout(150);

  const after = await page.evaluate(() => ({
    cells: Array.from(document.querySelectorAll("#inventoryActivationStrip .strip-cell strong")).map(s => Number(s.textContent || "0")),
    pickerCount: document.querySelector("#invPickerCount")?.textContent || "",
  }));
  assert.ok(after.cells[0] >= 1, `expected log-sources-enabled to be >=1 after toggle + score, got ${after.cells[0]}`);
  assert.ok(after.cells[1] >= 1, `expected components-activated to be >=1, got ${after.cells[1]}`);
  assert.match(after.pickerCount, /\d+ enabled/, `picker count chip should report enabled count, got: ${after.pickerCount}`);

  await page.context().close();
});

test("default-off: a fresh inventory shows zero coverage; personas with scores still light up via implicit-enable (chunk 19)", async () => {
  // chunk 19: every log source ships disabled by default. Without a
  // saved inventory entry (or with `enabled: false`), a log source
  // contributes 0 to coverage. Existing personas +
  // inventory.example.yaml omit the `enabled:` field but ship
  // `score > 0` rows; the importer infers enabled = true from score
  // so they continue working.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // Reset inventory to baseline.
  await page.click("#resetInventoryBtn");
  await page.waitForTimeout(150);

  // Summary pills should report 0 log sources scored on a fresh
  // inventory (default-off).
  const baseline = await page.evaluate(() => {
    const pills = Array.from(document.querySelectorAll("#inventorySummary .pill strong")).map(s => s.textContent || "");
    // pill 0: "X / Y log sources scored"; pill 1: "X / Y data components covered"
    const lsScored = Number((pills[0] || "0").split("/")[0].trim());
    const compsCovered = Number((pills[1] || "0").split("/")[0].trim());
    return { lsScored, compsCovered };
  });
  assert.equal(baseline.lsScored, 0, `default-off: expected 0 log sources scored on a fresh inventory, got ${baseline.lsScored}`);
  assert.equal(baseline.compsCovered, 0, `default-off: expected 0 components covered, got ${baseline.compsCovered}`);

  // Importing the example (which has `score:` but no `enabled:`
  // fields) should still light things up because the importer infers
  // enabled from score.
  await importInventory(page, "inventory.example.yaml");
  await page.waitForTimeout(150);
  const after = await page.evaluate(() => {
    const pills = Array.from(document.querySelectorAll("#inventorySummary .pill strong")).map(s => s.textContent || "");
    const lsScored = Number((pills[0] || "0").split("/")[0].trim());
    const compsCovered = Number((pills[1] || "0").split("/")[0].trim());
    return { lsScored, compsCovered };
  });
  assert.ok(after.lsScored >= 5, `expected the imported example to enable >=5 log sources, got ${after.lsScored}`);
  assert.ok(after.compsCovered >= 1, `expected at least one component covered by the imported example, got ${after.compsCovered}`);

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
  // chunk 9: the inventory tab has a "Group by" toggle. By-component is
  // the default (chunk N) but by-name remains as an alternate view that
  // surfaces every channel of one tool side-by-side. Switch to it
  // explicitly here so this test exercises that mode.
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

  // Switch to the by-name view.
  await page.evaluate(() => {
    const r = document.querySelector('input[name="inventoryGrouping"][value="name"]');
    if (r) { r.checked = true; r.dispatchEvent(new Event("change", { bubbles: true })); }
  });
  await page.waitForTimeout(150);
  const grouping = await page.evaluate(() => document.querySelector('input[name="inventoryGrouping"][value="name"]')?.checked);
  assert.equal(grouping, true, "by-name radio should be checked after switching");

  // Ensure the sysmon banner is expanded. Auto-expand may have already
  // opened it (chunk N) — clicking toggles, so only click when needed.
  await page.evaluate(() => {
    const wrap = document.querySelector('[data-components-for="name:sysmon"]');
    if (!wrap || !wrap.classList.contains("open")) {
      document.querySelector('[data-toggle="name:sysmon"]')?.click();
    }
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

  // Switch to the by-name view (chunk N made by-component the default;
  // the per-name "+ Add channel" form lives in by-name only).
  await page.evaluate(() => {
    const r = document.querySelector('input[name="inventoryGrouping"][value="name"]');
    if (r) { r.checked = true; r.dispatchEvent(new Event("change", { bubbles: true })); }
  });
  await page.waitForTimeout(150);

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

  // Ensure every parent is expanded so the nested log-source selects
  // are in the DOM. Auto-expand (chunk N) may have already opened the
  // groups that contain scored rows, so click only the still-collapsed
  // ones — clicking again would re-collapse them.
  await page.evaluate(() => {
    document.querySelectorAll("#inventoryTable [data-toggle]").forEach(t => {
      const id = t.getAttribute("data-toggle");
      const wrap = document.querySelector(`[data-components-for="${id}"]`);
      if (!wrap || !wrap.classList.contains("open")) t.click();
    });
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

test("by-component view (default): renders Data Component → Log Source → Channel hierarchy with channels unticked", async () => {
  // chunk N: the inventory tab merges the log-source and data-component
  // objects under one DC → LS → Channel hierarchy. By-component is the
  // default. Pick one component (e.g. "Process Creation"), expand it,
  // and assert there's at least one log-source sub-group with at least
  // one channel row, and that nothing is ticked on a cold inventory.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // The default radio should be by-component.
  const grouping = await page.evaluate(() =>
    document.querySelector('input[name="inventoryGrouping"][value="component"]')?.checked);
  assert.equal(grouping, true, "by-component should be the default grouping");

  // Find a component group containing the term 'Process' (offline bundle
  // ships several — Process Creation, Process Termination, etc.).
  const dcId = await page.evaluate(() => {
    for (const r of document.querySelectorAll("#inventoryTable .ds-row[data-ds-id]")) {
      const name = r.querySelector(".ds-name")?.textContent || "";
      if (/process/i.test(name)) return r.getAttribute("data-ds-id");
    }
    return null;
  });
  assert.ok(dcId, "expected a 'Process'-something component group on cold load");

  // Expand it and inspect the structure.
  await page.evaluate(id => document.querySelector(`[data-toggle="${id}"]`)?.click(), dcId);
  await page.waitForTimeout(150);

  const detail = await page.evaluate(id => {
    const wrap = document.querySelector(`[data-components-for="${id}"]`);
    if (!wrap) return null;
    const subs = wrap.querySelectorAll(".ls-subgroup");
    const channels = wrap.querySelectorAll(".dc-row.by-name-row");
    const enables = Array.from(wrap.querySelectorAll("input[type=checkbox][data-ls-enable]"));
    const scores = Array.from(wrap.querySelectorAll("select[data-kind='ls']"));
    return {
      subgroups: subs.length,
      channels: channels.length,
      enableCount: enables.length,
      enableChecked: enables.filter(b => b.checked).length,
      scoreNonZero: scores.filter(s => Number(s.value) > 0).length,
    };
  }, dcId);
  assert.ok(detail, "expected an open ds-components wrapper for the chosen component");
  assert.ok(detail.subgroups >= 1, `expected >=1 .ls-subgroup under the component, got ${detail.subgroups}`);
  assert.ok(detail.channels >= 1, `expected >=1 channel row, got ${detail.channels}`);
  assert.equal(detail.enableChecked, 0, `every channel should default unticked, got ${detail.enableChecked}/${detail.enableCount}`);
  assert.equal(detail.scoreNonZero, 0, `every channel score should default 0, got ${detail.scoreNonZero}`);

  // Tick one channel — the row should pick up the active styling and
  // the inventorySummary "log sources scored" pill should not move
  // (score is still 0; only the active flag changed).
  const firstKey = await page.evaluate(id => {
    const cb = document.querySelector(`[data-components-for="${id}"] input[type=checkbox][data-ls-enable]`);
    if (!cb) return null;
    cb.checked = true;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
    return cb.getAttribute("data-ls-enable");
  }, dcId);
  assert.ok(firstKey, "expected an enable checkbox to tick");
  await page.waitForTimeout(150);
  const afterTick = await page.evaluate(k => {
    const cb = document.querySelector(`input[type=checkbox][data-ls-enable="${k}"]`);
    return { checked: !!cb?.checked, parked: cb?.closest(".dc-row.by-name-row")?.classList.contains("parked") };
  }, firstKey);
  assert.equal(afterTick.checked, true, "ticked checkbox should remain checked after re-render");
  assert.equal(afterTick.parked, false, "active row should not have .parked styling");

  await page.context().close();
});

test("on cold inventory + cold threats every selectable item is unticked by default", async () => {
  // chunk N: a fresh user (no imported inventory, no picked threats)
  // should see every log-source channel as unticked / inactive and
  // every threat group as unselected. The previous default rendered
  // bundle log sources with the "enabled" checkbox already ticked,
  // which contradicted the workflow ("manually select the log
  // sources you have"). Score is already 0 for every channel; this
  // test guards the matching enable/checked default.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  // Inventory: open every group so all channel checkboxes are in the DOM.
  await activateTab(page, "inventory");
  await page.evaluate(() => {
    document.querySelectorAll("#inventoryTable [data-toggle]").forEach(t => {
      const id = t.getAttribute("data-toggle");
      const wrap = document.querySelector(`[data-components-for="${id}"]`);
      if (!wrap || !wrap.classList.contains("open")) t.click();
    });
  });
  await page.waitForTimeout(150);

  const inv = await page.evaluate(() => {
    const enable = Array.from(document.querySelectorAll("#inventoryTable input[type=checkbox][data-ls-enable]"));
    const score = Array.from(document.querySelectorAll("#inventoryTable select[data-kind='ls']"));
    return {
      enableTotal: enable.length,
      enableChecked: enable.filter(b => b.checked).length,
      scoreTotal: score.length,
      scoreNonZero: score.filter(s => Number(s.value) > 0).length,
    };
  });
  assert.ok(inv.enableTotal > 0, `expected at least one enable checkbox after expansion, got ${inv.enableTotal}`);
  assert.equal(inv.enableChecked, 0, `cold inventory: every channel should default unchecked, got ${inv.enableChecked}/${inv.enableTotal} checked`);
  assert.equal(inv.scoreNonZero, 0, `cold inventory: every channel score should default 0, got ${inv.scoreNonZero}/${inv.scoreTotal} non-zero`);

  // Threats: every group checkbox should default unchecked.
  await activateTab(page, "threats");
  const thr = await page.evaluate(() => {
    const boxes = Array.from(document.querySelectorAll("#groupList input[type=checkbox][data-gid]"));
    return { total: boxes.length, checked: boxes.filter(b => b.checked).length };
  });
  assert.ok(thr.total > 0, `expected at least one group checkbox, got ${thr.total}`);
  assert.equal(thr.checked, 0, `cold threats: every group should default unselected, got ${thr.checked}/${thr.total} selected`);

  await page.context().close();
});

test("inventory tab is fast on cold load: collapsed groups don't render channel rows", async () => {
  // chunk N: previously every group's <ds-components> wrapper rendered
  // every channel row + score select into the DOM, hidden via
  // display:none until expansion. With hundreds of bundle log sources
  // this used to crash the page. Inner rows are now emitted only when
  // a group is expanded, and the cold view (no inventory) emits header-
  // only nodes for every group.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");
  const cold = await page.evaluate(() => ({
    groups: document.querySelectorAll("#inventoryTable .ds-row[data-ds-id]").length,
    openSections: document.querySelectorAll("#inventoryTable .ds-components.open").length,
    selects: document.querySelectorAll("#inventoryTable select[data-kind='ls']").length,
  }));
  assert.ok(cold.groups > 0, `expected at least one group header on cold load, got ${cold.groups}`);
  assert.equal(cold.openSections, 0, `cold inventory should render zero open .ds-components, got ${cold.openSections}`);
  assert.equal(cold.selects, 0, `cold inventory should render zero score selects, got ${cold.selects}`);

  // Clicking a group's toggle expands it lazily — the inner channel
  // rows appear on demand.
  const firstId = await page.evaluate(() => document.querySelector("#inventoryTable [data-toggle]")?.getAttribute("data-toggle"));
  assert.ok(firstId, "expected at least one toggle button");
  await page.evaluate(id => document.querySelector(`[data-toggle="${id}"]`).click(), firstId);
  await page.waitForTimeout(120);
  const afterToggle = await page.evaluate(id => ({
    open: document.querySelectorAll("#inventoryTable .ds-components.open").length,
    rowsForGroup: document.querySelectorAll(`[data-components-for="${id}"] .dc-row.by-name-row`).length,
  }), firstId);
  assert.equal(afterToggle.open, 1, `expanding one group should produce exactly one open section, got ${afterToggle.open}`);
  assert.ok(afterToggle.rowsForGroup >= 1, `expanded group should emit at least one channel row, got ${afterToggle.rowsForGroup}`);

  await page.context().close();
});

test("inventory text filter narrows visible groups and forces matches open", async () => {
  // chunk N: the inventory view applies state.filters.ds across the
  // hierarchy. A search term hides non-matching groups entirely (so
  // 100s of unrelated banners aren't rebuilt on every keystroke) and
  // forces matching groups to render expanded so the user sees their
  // hits. The by-component view (default) matches the search against
  // log-source names + channels + the parent component name.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  // Snapshot the unfiltered group count.
  const baseline = await page.evaluate(() => document.querySelectorAll("#inventoryTable .ds-row[data-ds-id]").length);
  assert.ok(baseline > 1, `expected >1 group on cold inventory, got ${baseline}`);

  // Type a narrow filter; the input is debounced (~180ms) so wait it out.
  await page.fill("#dsFilter", "sysmon");
  await page.waitForTimeout(350);

  const filtered = await page.evaluate(() => {
    const groups = Array.from(document.querySelectorAll("#inventoryTable .ds-row[data-ds-id]"));
    const open = document.querySelectorAll("#inventoryTable .ds-components.open").length;
    // Visible groups must each contain at least one row referencing the
    // filter term (channel name or parent log-source name).
    const sysmonHits = groups.filter(g => {
      const id = g.getAttribute("data-ds-id");
      const wrap = document.querySelector(`[data-components-for="${id}"]`);
      return /sysmon/i.test(wrap?.textContent || "");
    }).length;
    return { groupCount: groups.length, sysmonHits, open };
  });
  assert.ok(filtered.groupCount >= 1, `expected at least one group matching 'sysmon', got ${filtered.groupCount}`);
  assert.ok(filtered.groupCount < baseline, `filter should hide non-matching groups (baseline ${baseline}, after ${filtered.groupCount})`);
  assert.equal(filtered.groupCount, filtered.sysmonHits, `every visible group should contain a sysmon row, got ${filtered.sysmonHits}/${filtered.groupCount}`);
  assert.ok(filtered.open >= 1, `matching groups should render expanded under an active filter, got ${filtered.open} open sections`);

  // Clearing the filter restores the full set without crashing.
  await page.fill("#dsFilter", "");
  await page.waitForTimeout(350);
  const restored = await page.evaluate(() => document.querySelectorAll("#inventoryTable .ds-row[data-ds-id]").length);
  assert.equal(restored, baseline, `clearing the filter should restore all ${baseline} groups, got ${restored}`);

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
