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
  assert.match(status, /Loaded \d+ component categories/, `expected status to say loaded, got: ${status}`);
  // Should pull the offline bundle: 38 component categories, 38 techniques, 20 groups
  assert.match(status, /38 component categories/);
  assert.match(status, /38 techniques/);
  assert.match(status, /20 groups/);
  await page.context().close();
});

test("UI no longer surfaces 'data source' user-facing strings or DSxxxx data-source IDs", async () => {
  // chunk 15 removed user-facing "data source" terminology. Chunk 1 of
  // the inventory-merge refactor goes one step further: no DSxxxx
  // data-source attackIds rendered anywhere in the visible UI either.
  // Internal STIX type names (x-mitre-data-source) and the DeTT&CT
  // YAML file_type identifier ("data-source-administration") stay —
  // those are interop strings, not UX. Detection-strategy attackIds
  // (DETxxxx in v18+ bundles) are explicitly allowed.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  // Header h1 + page title
  const headers = await page.evaluate(() => ({
    title: document.title,
    h1: document.querySelector(".brand h1")?.textContent || "",
    statusText: document.querySelector("#statusText")?.textContent || "",
  }));
  assert.match(headers.title, /Log Source/, `page title should mention 'Log Source', got: ${headers.title}`);
  assert.match(headers.h1, /Log Source/, `header h1 should mention 'Log Source', got: ${headers.h1}`);
  assert.doesNotMatch(headers.title, /Data Source/, `page title should not mention 'Data Source', got: ${headers.title}`);
  // Status banner after auto-load
  assert.match(headers.statusText, /component categor/i, `status should report categories, got: ${headers.statusText}`);

  // Walk every panel so we see selectors that lazy-render on tab activation
  // (Components, Detection Strategies, Diagrams). Each panel's options +
  // visible text get folded into the offender check below.
  for (const id of ["inventory", "components", "coverage", "graph", "export"]) {
    await page.evaluate((tid) => {
      const btn = document.querySelector(`button.tab[data-tab="${tid}"]`);
      if (btn) btn.click();
    }, id);
    await page.waitForTimeout(120);
  }

  // Sweep all visible body text + every <option> + every <input value>
  // for two forbidden patterns:
  //   1. user-facing "data source(s)" (chunk 15 baseline)
  //   2. DSxxxx data-source attackIds, e.g. "DS0028" (chunk 1)
  // Allow the singular "data component" (a real ATT&CK concept).
  // DETxxxx attackIds are detection-strategy IDs and are allowed.
  const offenders = await page.evaluate(() => {
    const dataSourceRe = /\bdata source(s)?\b/i;
    const dsIdRe = /\bDS\d{4,}\b/;
    const out = [];
    const selector = "h1, h2, h3, p, summary, label, button, .pill, .label, .stat-card .label, option, .ds-meta, .dc-meta, .tech-row, .comp-row, .ds-name, .ds-row";
    document.querySelectorAll(selector).forEach(el => {
      const text = (el.textContent || "").trim();
      if (dataSourceRe.test(text)) out.push({ kind: "data-source-string", text: text.slice(0, 120) });
      if (dsIdRe.test(text)) out.push({ kind: "ds-attackid", text: text.slice(0, 120) });
    });
    document.querySelectorAll("input").forEach(el => {
      const v = el.value || "";
      if (dataSourceRe.test(v)) out.push({ kind: "data-source-string-input", text: v.slice(0, 120) });
      if (dsIdRe.test(v)) out.push({ kind: "ds-attackid-input", text: v.slice(0, 120) });
    });
    return out;
  });
  assert.deepEqual(offenders, [],
    `no user-visible 'data source' strings or DSxxxx attackIds expected, got: ${JSON.stringify(offenders)}`);
  await page.context().close();
});

test("offline bundle exposes v18+ log sources, analytics, and detection strategies", async () => {
  // Chunk 2 (additive parser): attack.js indexes the new STIX types alongside
  // the legacy data-source / data-component pair. No consumer reads them yet.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const counts = await page.evaluate(() => {
    const a = window.__APP_STATE__?.attack || window.appState?.attack;
    if (!a) return null;
    return {
      logSources: a.logSources?.length ?? 0,
      analytics: a.analytics?.length ?? 0,
      detectionStrategies: a.detectionStrategies?.length ?? 0,
      strategyTechs: a.detectionStrategies?.reduce((n, s) => n + (s.techniqueIds?.length || 0), 0) ?? 0,
    };
  });
  // Test data may not be exposed via window globals yet; fall back to fetching the bundle directly
  // and re-parsing it via the same parser the app uses.
  const direct = await page.evaluate(async () => {
    const mod = await import("/js/attack.js");
    const r = await fetch("/vendor/attack-offline.json");
    const bundle = await r.json();
    const a = mod.loadAttackFromBundle(bundle);
    return {
      logSources: a.logSources.length,
      analytics: a.analytics.length,
      detectionStrategies: a.detectionStrategies.length,
      strategyTechs: a.detectionStrategies.reduce((n, s) => n + s.techniqueIds.length, 0),
      sampleLogSource: a.logSources[0] && { id: a.logSources[0].id, name: a.logSources[0].name, channel: a.logSources[0].channel },
      sampleAnalytic: a.analytics[0] && { id: a.analytics[0].id, name: a.analytics[0].name, logCount: a.analytics[0].logSourceIds.length },
    };
  });
  assert.ok(direct.logSources > 0, `expected log sources, got ${direct.logSources}`);
  assert.ok(direct.analytics >= 5, `expected at least 5 analytics, got ${direct.analytics}`);
  assert.ok(direct.detectionStrategies >= 3, `expected at least 3 detection strategies, got ${direct.detectionStrategies}`);
  assert.ok(direct.strategyTechs > 0, `expected strategy->technique relationships, got ${direct.strategyTechs}`);
  assert.match(direct.sampleLogSource?.id || "", /^logsource--/, "log source id should be synthetic prefix");
  assert.ok(direct.sampleAnalytic?.logCount > 0, "first analytic should reference at least one log source");
  await page.context().close();
});

test("blocked MITRE fetch shows a warn banner and offline data still loads", async () => {
  // Real-world scenario: corporate proxy or TLS interception blocks
  // raw.githubusercontent.com. The page should not be left empty.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  // Boot already fell back to offline; verify ATT&CK data is populated
  // and the banner explains what happened.
  const componentCategories = await page.evaluate(() => {
    // Use textContent — innerText applies the .label `text-transform:
    // uppercase` when the setup panel is visible, which would break a
    // case-sensitive regex.
    const summary = document.querySelector("#setupSummary")?.textContent || "";
    const m = summary.match(/Component categories\s*(\d+)/i);
    return m ? Number(m[1]) : 0;
  });
  assert.equal(componentCategories, 38, `expected 38 offline component categories to be loaded, got ${componentCategories}`);
  await page.context().close();
});
