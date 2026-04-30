// Shared Playwright harness used by every test file under tests/e2e/.
// Each test gets its own isolated browser context (fresh localStorage,
// fresh IndexedDB, fresh viewport) so suites are order-independent.

import { resolve } from "node:path";
import { existsSync } from "node:fs";

// In the local sandbox Playwright lives at /opt/node22/lib/node_modules; in CI
// it's installed via `npm install --no-save playwright@1.56.1` and resolved
// relative to the repo. Try the sandbox path first, fall back to the standard
// node resolution.
const SANDBOX_PLAYWRIGHT = "/opt/node22/lib/node_modules/playwright/index.mjs";
const playwright = await import(existsSync(SANDBOX_PLAYWRIGHT) ? SANDBOX_PLAYWRIGHT : "playwright");
const { chromium } = playwright;

export const REPO_ROOT   = resolve(import.meta.dirname, "..");
export const SAMPLES_DIR = resolve(REPO_ROOT, "samples");
export const ORIGIN      = process.env.BASE_URL || "http://localhost:8765";

const localChrome = "/opt/pw-browsers/chromium-1194/chrome-linux/chrome";
const launchOpts = {
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
};
if (existsSync(localChrome)) launchOpts.executablePath = localChrome;

let _browser;
export async function getBrowser() {
  if (!_browser) _browser = await chromium.launch(launchOpts);
  return _browser;
}
export async function closeBrowser() {
  if (_browser) { await _browser.close(); _browser = null; }
}

// Build a fresh page inside its own context. `viewport` defaults to desktop;
// pass `{ width: 390, height: 844 }` for mobile. `blockExternal: true`
// simulates the user's "GitHub raw + jsDelivr blocked" environment.
export async function newPage({ viewport = { width: 1280, height: 900 }, blockExternal = false } = {}) {
  const browser = await getBrowser();
  const ctx = await browser.newContext({ viewport });
  if (blockExternal) {
    await ctx.route("**/raw.githubusercontent.com/**", r => r.abort("connectionrefused"));
    await ctx.route("**/cdn.jsdelivr.net/**",          r => r.abort("connectionrefused"));
  }
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push({ kind: "pageerror", msg: e.message }));
  page.on("console", m => { if (m.type() === "error" && !m.text().includes("favicon")) errors.push({ kind: "console", msg: m.text() }); });
  page.on("requestfailed", r => {
    if (r.url().includes("favicon")) return;
    errors.push({ kind: "request", msg: `${r.failure()?.errorText} ${r.url()}` });
  });
  page._capturedErrors = errors;
  return page;
}

// Boot the app and wait until either the offline bundle has loaded or a
// banner explains why it didn't — i.e. the app is in a settled state.
export async function bootApp(page) {
  await page.goto(`${ORIGIN}/`, { waitUntil: "networkidle" });
  await page.waitForFunction(() => {
    const s = document.querySelector("#statusText")?.textContent || "";
    return /Loaded \d+ data sources/.test(s) || /failed/i.test(s) || /Couldn't/i.test(s);
  }, { timeout: 15_000 });
  // Give renderInventory a tick to flush
  await page.waitForTimeout(150);
}

export async function activateTab(page, id) {
  const onMobile = await page.evaluate(() => getComputedStyle(document.querySelector(".tabs")).display === "none");
  if (onMobile) await page.selectOption("#tabsMobile", id);
  else await page.click(`button.tab[data-tab="${id}"]`);
  await page.waitForTimeout(150);
}

export async function importInventory(page, filename) {
  const path = resolve(SAMPLES_DIR, filename);
  await page.setInputFiles("#inventoryFile", path);
  // Wait until status text confirms either success or failure.
  await page.waitForFunction(() => {
    const s = document.querySelector("#statusText")?.textContent || "";
    return /Imported|failed|error/i.test(s);
  }, { timeout: 5000 });
  await page.waitForTimeout(200);
}

export async function importThreats(page, filename) {
  const path = resolve(SAMPLES_DIR, filename);
  await page.setInputFiles("#groupsFile", path);
  await page.waitForFunction(() => {
    const s = document.querySelector("#statusText")?.textContent || "";
    return /Imported|failed|error/i.test(s);
  }, { timeout: 5000 });
  await page.waitForTimeout(200);
}

// Convenience: read a string of "stat" cards as a flat dict.
export async function readStats(page, selector) {
  return await page.evaluate(sel => {
    const out = {};
    document.querySelectorAll(`${sel} .stat-card`).forEach(card => {
      const label = card.querySelector(".label")?.textContent?.trim();
      const value = card.querySelector(".value")?.textContent?.trim();
      if (label) out[label] = value;
    });
    return out;
  }, selector);
}

// Inventory summary pills are not stat-cards; read them separately.
export async function readInventorySummary(page) {
  return await page.evaluate(() => {
    const out = {};
    document.querySelectorAll("#inventorySummary .pill").forEach(p => {
      const strong = p.querySelector("strong")?.textContent?.trim();
      const label = p.textContent.replace(strong || "", "").trim();
      if (label) out[label] = strong;
    });
    return out;
  });
}

// Number of inventory rows whose score select is non-zero.
export async function countScoredInventoryRows(page) {
  return await page.evaluate(() => {
    let n = 0;
    document.querySelectorAll("#inventoryTable .ds-row:not(.header) select[data-kind='ds']").forEach(s => { if (Number(s.value) > 0) n++; });
    return n;
  });
}
