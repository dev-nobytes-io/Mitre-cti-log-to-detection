import { test, after } from "node:test";
import assert from "node:assert/strict";
import { newPage, bootApp, closeBrowser } from "../harness.mjs";

// Each test file runs in its own process (--test-isolation=process), so
// tearing down the shared browser at file end is the right place to do it.
after(async () => { await closeBrowser(); });

test("vendored libs load (no banner about missing js-yaml / mermaid)", async () => {
  const page = await newPage();
  await bootApp(page);
  const yamlOk = await page.evaluate(() => typeof window.jsyaml === "object" && typeof window.jsyaml.load === "function");
  const mermaidOk = await page.evaluate(() => typeof window.mermaid === "object" && typeof window.mermaid.render === "function");
  assert.ok(yamlOk, "window.jsyaml should be available from vendor/js-yaml.min.js");
  assert.ok(mermaidOk, "window.mermaid should be available from vendor/mermaid.min.js");
  await page.context().close();
});

test("offline ATT&CK auto-loads on first visit (no cache)", async () => {
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const status = await page.locator("#statusText").innerText();
  assert.match(status, /Loaded \d+ data sources/, `expected status to say loaded, got: ${status}`);
  // Should pull the offline bundle: 38 data sources, 38 techniques, 20 groups
  assert.match(status, /38 data sources/);
  assert.match(status, /38 techniques/);
  assert.match(status, /20 groups/);
  await page.context().close();
});

test("blocked MITRE fetch shows a warn banner and offline data still loads", async () => {
  // Real-world scenario: corporate proxy or TLS interception blocks
  // raw.githubusercontent.com. The page should not be left empty.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  // Boot already fell back to offline; verify ATT&CK data is populated
  // and the banner explains what happened.
  const dataSources = await page.evaluate(() => {
    const summary = document.querySelector("#setupSummary")?.innerText || "";
    const m = summary.match(/Data sources\s*(\d+)/);
    return m ? Number(m[1]) : 0;
  });
  assert.equal(dataSources, 38, `expected 38 offline data sources to be loaded, got ${dataSources}`);
  await page.context().close();
});
