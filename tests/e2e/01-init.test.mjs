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

test("offline bundle exposes ATT&CK mitigations (course-of-action + mitigates)", async () => {
  // Additive parser chunk: attack.js indexes course-of-action objects and
  // `mitigates` relationships alongside the existing detects/uses rels. No
  // UI consumer yet — mirrors how log sources/analytics/strategies landed.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const direct = await page.evaluate(async () => {
    const mod = await import("/js/attack.js");
    const r = await fetch("/vendor/attack-offline.json");
    const bundle = await r.json();
    const a = mod.loadAttackFromBundle(bundle);
    const t1078 = a.techniqueByAttackId.get("T1078");
    const m1032 = a.mitigationByAttackId.get("M1032");
    return {
      mitigations: a.mitigations.length,
      sampleMitigation: a.mitigations[0] && { attackId: a.mitigations[0].attackId, name: a.mitigations[0].name },
      t1078MitigationIds: (t1078?.mitigationIds || []).map(id => a.mitigationById.get(id)?.attackId).sort(),
      m1032TechniqueIds: (m1032?.techniqueIds || []).map(id => a.techniqueById.get(id)?.attackId).sort(),
    };
  });
  assert.equal(direct.mitigations, 26, `expected 26 mitigations, got ${direct.mitigations}`);
  assert.match(direct.sampleMitigation?.attackId || "", /^M\d{4}$/, "mitigation attackId should look like M1234");
  assert.ok(direct.t1078MitigationIds.includes("M1032"), `expected T1078 to be mitigated by M1032 (MFA), got ${direct.t1078MitigationIds}`);
  assert.ok(direct.m1032TechniqueIds.includes("T1078"), `expected M1032 to mitigate T1078, got ${direct.m1032TechniqueIds}`);
  await page.context().close();
});

test("D3FEND sub-mitigation mappings load and attach onto ATT&CK mitigations", async () => {
  // Additive parser chunk 2: js/d3fend.js loads the vendored ATT&CK
  // Mitigations -> D3FEND mapping and merges D3FEND sub-mitigations onto
  // the mitigations parsed from the ATT&CK bundle (chunk 1). No UI
  // consumer yet.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const direct = await page.evaluate(async () => {
    const attackMod = await import("/js/attack.js");
    const d3fendMod = await import("/js/d3fend.js");
    const bundle = await (await fetch("/vendor/attack-offline.json")).json();
    const a = attackMod.loadAttackFromBundle(bundle);
    const d3fendByAttackId = await d3fendMod.loadD3fendMitigations();
    d3fendMod.attachD3fend(a, d3fendByAttackId);
    const m1032 = a.mitigationByAttackId.get("M1032");
    const m1053 = a.mitigationByAttackId.get("M1053"); // Data Backup — real D3FEND mapping has no sub-techniques
    const mfa = (m1032?.d3fend || []).find(d => d.id === "D3-MFA");
    return {
      d3fendMitigationCount: d3fendByAttackId.size,
      m1032D3fend: (m1032?.d3fend || []).map(d => d.id),
      m1053D3fend: m1053?.d3fend || [],
      everyMitigationHasD3fendArray: a.mitigations.every(m => Array.isArray(m.d3fend)),
      everyD3fendEntryHasNistArray: a.mitigations.every(m => (m.d3fend || []).every(d => Array.isArray(d.nist))),
      mfaNist: mfa?.nist || [],
    };
  });
  assert.ok(direct.d3fendMitigationCount >= 40, `expected ~42 D3FEND mitigation entries, got ${direct.d3fendMitigationCount}`);
  assert.ok(direct.m1032D3fend.includes("D3-MFA"), `expected M1032 to map to D3-MFA, got ${direct.m1032D3fend}`);
  assert.deepEqual(direct.m1053D3fend, [], "M1053 (Data Backup) has no D3FEND sub-mitigations upstream");
  assert.ok(direct.everyMitigationHasD3fendArray, "every mitigation should have a d3fend array, even if empty");
  assert.ok(direct.everyD3fendEntryHasNistArray, "every D3FEND sub-mitigation should have a nist array, even if empty");
  assert.ok(direct.mfaNist.length > 0, `expected D3-MFA to map to at least one NIST 800-53 control, got ${JSON.stringify(direct.mfaNist)}`);
  assert.ok(direct.mfaNist.some(c => c.startsWith("IA-2") || c.startsWith("AC-2")), `expected D3-MFA's NIST controls to include an IA-2/AC-2 family control, got ${JSON.stringify(direct.mfaNist)}`);
  await page.context().close();
});

test("mitigation maturity scores persist and round-trip through export/import", async () => {
  // Additive data-layer chunk: preventive-control (ATT&CK mitigation)
  // scoring is independent of the detective log-source/analytic/strategy
  // chain. No UI consumer yet.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const result = await page.evaluate(async () => {
    const inv = await import("/js/inventory.js");
    let state = inv.emptyInventory();
    inv.setMitigationScore(state, "M1032", 4, "Okta MFA everywhere");
    inv.setMitigationScore(state, "M1053", 2);
    const before = inv.effectiveMitigationScores(state);

    const yaml = inv.exportYaml(state);
    const reimported = inv.importYaml(yaml);
    const afterYaml = inv.effectiveMitigationScores(reimported);

    const json = inv.exportJson(state);
    const reimportedJson = inv.importJson(json);
    const afterJson = inv.effectiveMitigationScores(reimportedJson);

    return {
      beforeM1032: before.get("M1032"),
      beforeM1053: before.get("M1053"),
      afterYamlM1032: afterYaml.get("M1032"),
      afterJsonM1032: afterJson.get("M1032"),
      unscoredIsUndefined: before.get("M1099"),
    };
  });
  assert.deepEqual(result.beforeM1032, { score: 4, comment: "Okta MFA everywhere" });
  assert.deepEqual(result.beforeM1053, { score: 2, comment: "" });
  assert.deepEqual(result.afterYamlM1032, { score: 4, comment: "Okta MFA everywhere" }, "YAML export/import should round-trip mitigation scores");
  assert.deepEqual(result.afterJsonM1032, { score: 4, comment: "Okta MFA everywhere" }, "JSON export/import should round-trip mitigation scores");
  assert.equal(result.unscoredIsUndefined, undefined, "an unscored mitigation should be absent from the map, not defaulted to 0");
  await page.context().close();
});

test("custom mappings: add a custom mitigation + ISM/technique relations, merge idempotently, round-trip through export", async () => {
  // Additive data-layer chunk: js/custom-mappings.js lets the app model
  // frameworks with no published ATT&CK crosswalk (ISM has none at all)
  // via user-entered objects/relations, merged onto the loaded AttackData
  // without mutating the original STIX-parsed data. No UI consumer yet.
  const page = await newPage({ blockExternal: true });
  await bootApp(page);
  const result = await page.evaluate(async () => {
    const attackMod = await import("/js/attack.js");
    const invMod = await import("/js/inventory.js");
    const cm = await import("/js/custom-mappings.js");
    const bundle = await (await fetch("/vendor/attack-offline.json")).json();
    const attack = attackMod.loadAttackFromBundle(bundle);
    const inv = invMod.emptyInventory();

    const t1486 = attack.techniqueByAttackId.get("T1486");
    const mid = cm.addCustomMitigation(inv, { name: "Air-gapped backup vault", description: "Offline immutable backups" });
    cm.addCustomRelation(inv, { sourceRef: mid, relation: "mitigates", targetRef: t1486.id, targetLabel: "T1486" });
    cm.addCustomRelation(inv, { sourceRef: mid, relation: "maps-to-ism", targetRef: "ISM-1622", targetLabel: "Backup and recovery" });
    // M1032 is a real, STIX-parsed mitigation — custom relations must not
    // disturb its existing official D3FEND data.
    const m1032Before = attack.mitigationByAttackId.get("M1032");
    const officialD3fendBefore = (m1032Before.d3fend || []).length;
    cm.addCustomRelation(inv, { sourceRef: "course-of-action--m-1032", relation: "maps-to-ism", targetRef: "ISM-0974", targetLabel: "MFA control" });

    cm.mergeCustomData(attack, inv);
    cm.mergeCustomData(attack, inv); // twice on purpose — must not double up

    const custom = attack.mitigationById.get(mid);
    const m1032After = attack.mitigationByAttackId.get("M1032");

    // Round-trip through YAML and JSON.
    const yaml = invMod.exportYaml(inv);
    const reimportedYaml = invMod.importYaml(yaml);
    const json = invMod.exportJson(inv);
    const reimportedJson = invMod.importJson(json);

    return {
      totalMitigations: attack.mitigations.length,
      customTechniqueIds: custom?.techniqueIds || [],
      customIsm: custom?.customIsm || [],
      t1486MitigationIds: (attack.techniqueByAttackId.get("T1486")?.mitigationIds || []),
      officialD3fendBefore,
      officialD3fendAfter: (m1032After.d3fend || []).length,
      m1032CustomIsm: m1032After.customIsm || [],
      yamlObjectCount: reimportedYaml.custom_objects.length,
      yamlRelationCount: reimportedYaml.custom_relations.length,
      jsonObjectCount: reimportedJson.custom_objects.length,
    };
  });
  assert.equal(result.totalMitigations, 27, `expected 26 real + 1 custom mitigation, got ${result.totalMitigations}`);
  assert.deepEqual(result.customTechniqueIds, ["attack-pattern--ap-1486"]);
  assert.deepEqual(result.customIsm, [{ id: "ISM-1622", name: "Backup and recovery", custom: true }]);
  assert.ok(result.t1486MitigationIds.some(id => id.startsWith("custom-mitigation-")), `expected T1486 to be linked to the custom mitigation, got ${result.t1486MitigationIds}`);
  assert.equal(result.officialD3fendAfter, result.officialD3fendBefore, "a custom ISM relation on M1032 must not disturb its official D3FEND data");
  assert.deepEqual(result.m1032CustomIsm, [{ id: "ISM-0974", name: "MFA control", custom: true }]);
  assert.equal(result.yamlObjectCount, 1, "custom_objects should round-trip through YAML");
  assert.equal(result.yamlRelationCount, 3, "custom_relations should round-trip through YAML");
  assert.equal(result.jsonObjectCount, 1, "custom_objects should round-trip through JSON");
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
