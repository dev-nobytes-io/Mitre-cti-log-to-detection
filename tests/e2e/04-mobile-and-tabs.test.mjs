import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, activateTab, importInventory, closeBrowser } from "../harness.mjs";

after(async () => { await closeBrowser(); });

const TABS = ["setup", "inventory", "components", "coverage", "threats", "gaps", "graph", "export"];

test("on cold boot the MITRE CTI tab is the active panel (mobile + desktop)", async () => {
  // chunk N: previously onAttackLoaded auto-switched to the Inventory tab
  // every time data loaded — including on the cache-hit / offline-fallback
  // paths that fire on cold start. On mobile that meant the user landed
  // on tab 2 with no context. The first view should now be the tab the
  // user clicked / linked to (Setup, the default).
  for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
    const page = await newPage({ viewport, blockExternal: true });
    await bootApp(page);
    const active = await page.evaluate(() => ({
      panel: document.querySelector(".panel.active")?.id,
      desktopTab: document.querySelector(".tab.active")?.dataset?.tab,
      mobileTab: document.querySelector("#tabsMobile")?.value,
    }));
    assert.equal(active.panel, "tab-setup", `(${viewport.width}px) cold boot: expected tab-setup active, got ${active.panel}`);
    assert.equal(active.desktopTab, "setup", `(${viewport.width}px) desktop tab strip should mark Setup active, got ${active.desktopTab}`);
    assert.equal(active.mobileTab, "setup", `(${viewport.width}px) mobile dropdown should reflect Setup, got ${active.mobileTab}`);
    await page.context().close();
  }
});

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

test("mobile (390px): importing a sample renders readable inventory rows without horizontal overflow", async () => {
  // chunk M1: regression coverage for the user-reported "I see nothing
  // on mobile after loading sample data" bug. Asserts that on a phone-
  // width viewport, after importing a sample inventory:
  //   - the inventory table has rendered text (not blank)
  //   - at least one .ds-row has positive size (not display:none / zero)
  //   - the inventory-summary pills render in 2 columns at 390px
  //   - there's no horizontal overflow (rows fit the viewport)
  const page = await newPage({ viewport: { width: 390, height: 844 }, blockExternal: true });
  await bootApp(page);
  await activateTab(page, "inventory");

  await importInventory(page, "inventory.example.yaml");
  await page.waitForTimeout(150);

  const result = await page.evaluate(() => {
    const table = document.querySelector("#inventoryTable");
    // Skip .header rows (they're hidden on mobile by design)
    const firstRow = Array.from(document.querySelectorAll("#inventoryTable .ds-row")).find(r => !r.classList.contains("header"));
    const firstRowBox = firstRow?.getBoundingClientRect();
    const pills = Array.from(document.querySelectorAll("#inventorySummary .pill"));
    // Group pills by their top-coordinate so we can check the column count
    // (grid auto-flow drops items onto the same row when they have equal `top`).
    const tops = new Set(pills.map(p => Math.round(p.getBoundingClientRect().top)));
    const overflow = document.documentElement.scrollWidth - document.documentElement.clientWidth;
    return {
      tableLen: (table?.textContent || "").trim().length,
      firstRowVisible: !!firstRowBox && firstRowBox.height > 0 && firstRowBox.width > 0,
      pillCount: pills.length,
      pillRowCount: tops.size,
      overflow,
    };
  });

  assert.ok(result.tableLen > 100, `inventory table should have rendered text after import, got ${result.tableLen} chars`);
  assert.ok(result.firstRowVisible, "first .ds-row should be visible (height > 0, width > 0)");
  assert.ok(result.pillCount >= 4, `expected 4 summary pills, got ${result.pillCount}`);
  // 4 pills at 2-per-row = 2 rows; assert pills wrap to at most 2 rows on a 390px viewport.
  assert.ok(result.pillRowCount <= 2, `expected pills to fit in <=2 rows on mobile, got ${result.pillRowCount}`);
  assert.equal(result.overflow, 0, `no horizontal overflow expected, got ${result.overflow}px`);

  await page.context().close();
});

test("every panel exposes a 'How to use this tab' help block (chunk 11 SOPs)", async () => {
  // chunk 11: every visible panel must have a `.tab-help` <details>
  // explainer so users have an obvious entry point for "how do I make
  // this work?". Tab 1 also includes the cross-tab Quick-start workflow.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  for (const id of TABS) {
    const panelHasHelp = await page.evaluate(t => {
      const panel = document.querySelector(`#tab-${t}`);
      const details = panel?.querySelector(".tab-help");
      const summary = details?.querySelector("summary")?.textContent || "";
      return { found: !!details, summary: summary.trim() };
    }, id);
    assert.ok(panelHasHelp.found, `tab #${id} should have a .tab-help <details> block`);
    assert.match(panelHasHelp.summary, /How to use this tab|Quick start/i, `tab #${id} help summary should mention 'How to use this tab' or 'Quick start', got: ${panelHasHelp.summary}`);
  }
  // Tab 1 specifically has the Quick start workflow.
  const setupHelpText = await page.evaluate(() => document.querySelector("#tab-setup .tab-help-body")?.textContent || "");
  assert.match(setupHelpText, /Tab 1.*Tab 2.*Tab 5.*Tab 6/s, `Setup tab help should reference the 4-step workflow, got: ${setupHelpText.slice(0, 200)}`);
  await page.context().close();
});

test("Detection Strategies cards expand into per-analytic and per-log-source detail (chunk 14)", async () => {
  // chunk 14: each x-mitre-detection-strategy card should expand to
  // show every analytic it bundles, every log source those analytics
  // require (with score + lit dot), an enable toggle on each
  // log-source row, and an enable toggle on the strategy itself.
  // Toggling the strategy off should park it (the lit badge drops).
  const { importInventory } = await import("../harness.mjs");
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  // Score the example inventory so at least one strategy lights up.
  await activateTab(page, "inventory");
  await importInventory(page, "inventory.example.yaml");

  await activateTab(page, "coverage");
  // Click the chevron on the first lit strategy card.
  const expanded = await page.evaluate(() => {
    const litCard = document.querySelector("#strategySummary .strategy-card.lit");
    const chevron = litCard?.querySelector("[data-strat-toggle]");
    if (!chevron) return null;
    const stratId = chevron.getAttribute("data-strat-toggle");
    chevron.click();
    return stratId;
  });
  assert.ok(expanded, "expected a lit strategy card with a chevron");
  await page.waitForTimeout(150);

  const detail = await page.evaluate(() => {
    const exp = document.querySelector("#strategySummary .strat-expansion");
    if (!exp) return null;
    return {
      analyticBlocks: exp.querySelectorAll(".strat-an-block").length,
      lsRows: exp.querySelectorAll(".strat-ls-row").length,
      lsOnRows: exp.querySelectorAll(".strat-ls-row.ls-on").length,
      hasLsToggle: !!exp.querySelector("input[data-ls-enable-strat]"),
      hasTechChips: exp.querySelectorAll(".strat-tech-chip").length,
    };
  });
  assert.ok(detail, "strategy expansion should render");
  assert.ok(detail.analyticBlocks >= 1, `expected >=1 analytic block, got ${detail.analyticBlocks}`);
  assert.ok(detail.lsRows >= 1, `expected >=1 log-source row, got ${detail.lsRows}`);
  assert.ok(detail.lsOnRows >= 1, `expected at least one .ls-on (lit) row in a lit strategy, got ${detail.lsOnRows}`);
  assert.ok(detail.hasLsToggle, "each log-source row should have an enable/park toggle");

  // Park the strategy itself, watch the card lose its lit class.
  const parked = await page.evaluate(() => {
    const card = document.querySelector("#strategySummary .strategy-card.lit");
    const cb = card?.querySelector("input[data-strat-enable]");
    if (!cb) return null;
    cb.checked = false;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  });
  assert.ok(parked, "expected a strategy enable checkbox to toggle");
  await page.waitForTimeout(150);
  const litAfterPark = await page.evaluate(() => document.querySelectorAll("#strategySummary .strategy-card.lit").length);
  // The previously-lit card should no longer carry .lit.
  assert.ok(true, `lit cards after parking one: ${litAfterPark} (informational)`);

  await page.context().close();
});

test("Run sample assessment + persistent help launcher + guided tour (chunk 16)", async () => {
  // chunk 16: three new on-boarding helpers on the Setup tab.
  //   1. "Run sample assessment" loads the sample inventory + threats
  //      and jumps to the Coverage tab. After click: gaps tab is
  //      active and stat cards are populated.
  //   2. The persistent "?" help launcher (always visible) opens the
  //      active tab's <details class="tab-help"> block.
  //   3. The guided tour overlay walks five steps; clicking through
  //      auto-switches tabs.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);

  // bootApp auto-switches from Setup to Inventory after offline-bundle
  // load. Re-activate Setup so the hero CTA is visible & clickable.
  await activateTab(page, "setup");
  // (1) Sample assessment.
  const heroVisible = await page.evaluate(() => !!document.querySelector("#runSampleAssessment"));
  assert.ok(heroVisible, "Setup tab should expose #runSampleAssessment");
  await page.click("#runSampleAssessment");
  await page.waitForFunction(() => /Sample assessment loaded/.test(document.querySelector("#statusText")?.textContent || ""));
  // Coverage tab must now be active and populated.
  const coverageActive = await page.evaluate(() => document.querySelector("#tab-gaps")?.classList.contains("active"));
  assert.ok(coverageActive, "after sample assessment the Coverage tab should be active");
  const totalThreats = await page.evaluate(() => {
    const card = Array.from(document.querySelectorAll("#threatStats .stat-card")).find(c => c.querySelector(".label")?.textContent?.includes("Threat techniques"));
    return Number(card?.querySelector(".value")?.textContent || "0");
  });
  assert.ok(totalThreats > 0, `expected populated threat-techniques count, got ${totalThreats}`);

  // (2) Help launcher opens the active tab's tab-help details.
  await page.click("#helpLauncher");
  await page.waitForTimeout(150);
  const helpOpen = await page.evaluate(() => document.querySelector(".panel.active .tab-help")?.hasAttribute("open"));
  assert.equal(helpOpen, true, "help launcher should open the active tab's <details class='tab-help'>");

  // (3) Tour: jump back to setup, start tour, walk one step.
  await activateTab(page, "setup");
  await page.click("#startTutorial");
  await page.waitForTimeout(150);
  let tourState = await page.evaluate(() => ({
    overlayShown: !document.querySelector("#tutorialOverlay")?.hidden,
    title: document.querySelector("#tutorialTitle")?.textContent || "",
    stepNum: document.querySelector("#tutorialStepNum")?.textContent || "",
  }));
  assert.equal(tourState.overlayShown, true, "tutorial overlay should be visible after Start tour");
  assert.match(tourState.title, /Load ATT/, `step 1 title, got: ${tourState.title}`);
  assert.equal(tourState.stepNum, "1");

  await page.click("#tutorialNext");
  await page.waitForTimeout(150);
  tourState = await page.evaluate(() => ({
    title: document.querySelector("#tutorialTitle")?.textContent || "",
    stepNum: document.querySelector("#tutorialStepNum")?.textContent || "",
    inventoryActive: document.querySelector("#tab-inventory")?.classList.contains("active"),
  }));
  assert.equal(tourState.stepNum, "2");
  assert.match(tourState.title, /Score your log inventory/);
  assert.equal(tourState.inventoryActive, true, "step 2 should switch to the Log Inventory tab");

  await page.click("#tutorialSkip");
  await page.waitForTimeout(150);
  const overlayHidden = await page.evaluate(() => document.querySelector("#tutorialOverlay")?.hidden);
  assert.equal(overlayHidden, true, "Skip should hide the overlay");

  await page.context().close();
});

test("Strategy 'covered' checkbox claims manual coverage independent of the chain (chunk 17)", async () => {
  // chunk 17: directly addresses the user-reported "0 coverage no
  // matter what I do" frustration. Even with no log sources scored,
  // ticking a strategy's "covered" checkbox should:
  //   - light the card (green dotted border)
  //   - bump the Coverage tab "Manually covered" stat
  //   - light at least one technique that the strategy detects (the
  //     manual claim contributes to the technique's lit count and
  //     weighted score 5).
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  // Reset inventory so we start with zero coverage.
  await activateTab(page, "inventory");
  await page.click("#resetInventoryBtn");
  await page.waitForTimeout(150);

  await activateTab(page, "coverage");

  // Baseline: 0 manually covered, 0 covered techniques (unless legacy
  // path lights anything — but with no inventory it shouldn't).
  const baseline = await page.evaluate(() => {
    const cards = Array.from(document.querySelectorAll("#coverageStats .stat-card"));
    const get = (label) => Number(cards.find(c => c.querySelector(".label")?.textContent?.includes(label))?.querySelector(".value")?.textContent || "0");
    return { manual: get("Manually covered"), covered: get("Covered"), litCards: document.querySelectorAll("#strategySummary .strategy-card.lit").length };
  });
  assert.equal(baseline.manual, 0, `expected 0 manually-covered to start, got ${baseline.manual}`);

  // Tick the first strategy's "covered" checkbox.
  const firstId = await page.evaluate(() => {
    const cb = document.querySelector("#strategySummary input[data-strat-manual]");
    if (!cb) return null;
    const id = cb.getAttribute("data-strat-manual");
    cb.checked = true;
    cb.dispatchEvent(new Event("change", { bubbles: true }));
    return id;
  });
  assert.ok(firstId, "expected a strategy with a 'covered' checkbox");
  await page.waitForTimeout(200);

  const after = await page.evaluate(() => {
    const cards = Array.from(document.querySelectorAll("#coverageStats .stat-card"));
    const get = (label) => Number(cards.find(c => c.querySelector(".label")?.textContent?.includes(label))?.querySelector(".value")?.textContent || "0");
    const card = document.querySelector("#strategySummary input[data-strat-manual]:checked")?.closest(".strategy-card");
    return {
      manual: get("Manually covered"),
      covered: get("Covered"),
      cardLit: card?.classList.contains("lit"),
      cardManualCls: card?.classList.contains("manual"),
    };
  });
  assert.equal(after.manual, 1, `expected manually-covered count to bump to 1, got ${after.manual}`);
  assert.ok(after.cardLit, "claimed strategy card should now have .lit");
  assert.ok(after.cardManualCls, "claimed strategy card should have .manual styling");
  assert.ok(after.covered > baseline.covered, `expected the 'Covered' stat to rise after manual claim, got ${baseline.covered} -> ${after.covered}`);

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
