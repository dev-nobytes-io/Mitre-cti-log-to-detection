import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, activateTab, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

const TABS = ["setup", "inventory", "components", "coverage", "threats", "gaps", "graph", "export"];

test("at phone width: tabs collapse to a select dropdown, no horizontal overflow", async () => {
  const page = await newPage({ viewport: { width: 390, height: 844 }, blockExternal: true });
  await bootApp(page);

  const tabsHidden = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs")).display === "none");
  assert.ok(tabsHidden, "desktop .tabs strip should be hidden at 390px width");

  const dropdownVisible = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs-mobile")).display !== "none");
  assert.ok(dropdownVisible, ".tabs-mobile <select> should be visible at 390px width");

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  assert.equal(overflow, 0, `body should not horizontally overflow, got ${overflow} px`);

  await page.context().close();
});

test("every tab activates and renders its panel without errors", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  for (const id of TABS) {
    await activateTab(page, id);
    const panelVisible = await page.evaluate(t => {
      const el = document.querySelector(`#tab-${t}`);
      return el && el.classList.contains("active");
    }, id);
    assert.ok(panelVisible, `panel #tab-${id} should be active after activateTab`);
  }
  // No page errors should have accumulated during tab navigation.
  const fatal = page._capturedErrors.filter(e => e.kind === "pageerror");
  assert.deepEqual(fatal, [], `no page errors expected, got: ${JSON.stringify(fatal)}`);
  await page.context().close();
});

test("Detection Strategies tab shows real STIX strategies + lit/unlit cards", async () => {
  // chunk 5: tab 4 gains a top section that lists every
  // x-mitre-detection-strategy. After importing inventory.example.yaml
  // (which scores log sources tied to a known analytic) at least one
  // strategy card should be marked .lit and the Detection Components
  // tab should expose log-source / analytic counts.
  const { importInventory } = await import("../harness.mjs");
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");

  await activateTab(page, "coverage");
  const summary = await page.evaluate(() => {
    const cards = document.querySelectorAll("#strategySummary .strategy-card");
    return {
      count: cards.length,
      lit: Array.from(cards).filter(c => c.classList.contains("lit")).length,
      countLabel: document.querySelector("#strategySummaryCount")?.textContent || "",
    };
  });
  assert.ok(summary.count >= 3, `expected >=3 strategy cards, got ${summary.count}`);
  assert.ok(summary.lit >= 1, `expected at least 1 lit strategy after scoring sysmon/1 etc., got ${summary.lit}`);
  assert.equal(summary.countLabel, String(summary.count), "summary count label should match card count");

  await activateTab(page, "components");
  const compStats = await page.evaluate(() => {
    const total = document.querySelector("#componentStats .stat-card .value")?.textContent;
    const cards = Array.from(document.querySelectorAll("#componentStats .stat-card"));
    const labels = cards.map(c => c.querySelector(".label")?.textContent?.trim());
    return { total, labels };
  });
  assert.ok(compStats.labels.includes("Log sources (total)"), `expected log-sources stat, got: ${JSON.stringify(compStats.labels)}`);
  assert.ok(compStats.labels.includes("Analytics (total)"), `expected analytics stat, got: ${JSON.stringify(compStats.labels)}`);

  await page.context().close();
});

test("Diagrams tab: log source utility cascade renders when log sources are picked", async () => {
  // chunk 8: a multi-select picker on the Diagrams tab drives a Mermaid
  // cascade Log Source -> Component -> Analytic -> Strategy -> Technique
  // -> Threat group. Empty selection should show a friendly empty state;
  // selecting a source that's referenced by analytics should produce an
  // SVG diagram.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  await activateTab(page, "graph");

  // Empty state first
  let placeholder = await page.evaluate(() => document.querySelector("#diagramLogSourceCascade")?.textContent || "");
  assert.match(placeholder, /Pick log sources/, `expected empty-state hint, got: ${placeholder}`);

  // Pick the first checkbox the picker rendered. The offline bundle ships
  // ~50+ log sources so there will always be at least one.
  const checked = await page.evaluate(() => {
    const box = document.querySelector("#logSourcePicker input[type=checkbox][data-ls-id]");
    if (!box) return null;
    box.checked = true;
    box.dispatchEvent(new Event("change", { bubbles: true }));
    return box.dataset.lsId;
  });
  assert.ok(checked, "picker should expose at least one log-source checkbox");

  await page.waitForTimeout(400);

  // Cascade should render an SVG, and the count chip must reflect 1 selected.
  const result = await page.evaluate(() => ({
    svg: !!document.querySelector("#diagramLogSourceCascade svg"),
    count: document.querySelector("#logSourcePickerCount")?.textContent || "",
  }));
  assert.ok(result.svg, "expected an SVG inside #diagramLogSourceCascade after picking a log source");
  assert.match(result.count, /1 selected/, `count chip should read '1 selected', got: ${result.count}`);

  // Clear restores the empty state.
  await page.click("#logSourcePickerClear");
  await page.waitForTimeout(150);
  placeholder = await page.evaluate(() => document.querySelector("#diagramLogSourceCascade")?.textContent || "");
  assert.match(placeholder, /Pick log sources/, `cleared cascade should return to empty state, got: ${placeholder}`);

  await page.context().close();
});

test("desktop layout still works (no mobile dropdown shown)", async () => {
  const page = await newPage({ viewport: { width: 1280, height: 900 }, blockExternal: true });
  await bootApp(page);
  const tabsVisible = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs")).display !== "none");
  assert.ok(tabsVisible, "desktop tab strip should be visible at 1280px width");
  const dropdownHidden = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs-mobile")).display === "none");
  assert.ok(dropdownHidden, ".tabs-mobile <select> should be hidden at 1280px width");
  await page.context().close();
});
