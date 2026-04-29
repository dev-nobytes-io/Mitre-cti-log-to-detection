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

test("desktop layout still works (no mobile dropdown shown)", async () => {
  const page = await newPage({ viewport: { width: 1280, height: 900 }, blockExternal: true });
  await bootApp(page);
  const tabsVisible = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs")).display !== "none");
  assert.ok(tabsVisible, "desktop tab strip should be visible at 1280px width");
  const dropdownHidden = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs-mobile")).display === "none");
  assert.ok(dropdownHidden, ".tabs-mobile <select> should be hidden at 1280px width");
  await page.context().close();
});
