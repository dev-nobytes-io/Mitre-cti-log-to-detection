import { loadAttack, loadAttackFromBundle, clearAttackCache, loadOfflineBundle } from "./attack.js";
import {
  loadInventory, saveInventory, resetInventory,
  effectiveComponentScores, setSourceScore, setComponentScore, setAllSources,
  exportYaml, importYaml, exportJson, importJson,
} from "./inventory.js";
import { computeCoverage } from "./coverage.js";
import { buildNavigatorLayer } from "./navigator.js";
import { conceptualDiagram, sourceDiagram, techniqueDiagram, overviewDiagram } from "./diagrams.js";
import {
  loadThreats, saveThreats, resetThreats,
  isGroupSelected, setGroupSelected, clearSelection,
  selectedGroups, gapAnalysis, buildThreatLayer,
  exportThreatsYaml, importThreatsYaml, importThreatsJson,
} from "./threats.js";

const state = {
  attack: null,
  inventory: loadInventory(),
  threats: loadThreats(),
  filters: {
    ds: "",
    platform: "",
    onlyScored: false,
    component: "",
    componentScore: "",
    tech: "",
    tactic: "",
    coverage: "",
    group: "",
    threatStatus: "",
  },
  expanded: new Set(),
  graph: {
    sourceId: "",
    techStixId: "",
    maxTech: 20,
    onlyCovered: false,
  },
  mermaidReady: false,
  mermaidSeq: 0,
};

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

function setStatus(text, kind = "") {
  const el = $("#status");
  $("#statusText").textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

// Re-render every view that depends on inventory or attack state. Cheap to
// run; coverage / mermaid are recomputed lazily and bail early when there's
// no attack data loaded.
function refreshAll() {
  renderInventory();
  renderComponents();
  renderCoverage();
  renderGraph();
  renderExport();
  renderThreats();
}

// Show a sticky banner across the top — stays visible until the user
// dismisses or the cause is resolved. Used for "library failed to load",
// import errors that are easy to miss in the small status text, etc.
function setBanner(message, kind = "error") {
  const el = $("#globalBanner");
  if (!el) return;
  if (!message) { el.hidden = true; el.innerHTML = ""; return; }
  el.hidden = false;
  el.className = `global-banner ${kind}`;
  el.innerHTML = `${message} <span style="margin-left:auto;cursor:pointer;font-weight:600" id="dismissBanner">×</span>`;
  el.querySelector("#dismissBanner")?.addEventListener("click", () => { el.hidden = true; });
}

// Detect if the bundled libs are usable. Shows a banner if not.
function checkVendorLibs() {
  const issues = [];
  if (typeof window.jsyaml === "undefined") issues.push("js-yaml");
  if (typeof window.mermaid === "undefined") issues.push("mermaid");
  if (issues.length) {
    setBanner(
      `Local libraries failed to load: ${issues.join(", ")}. ` +
      `Imports / diagrams won't work. Reload the page; if it persists, check that <code>vendor/</code> ships with the deployment.`,
      "error"
    );
    return false;
  }
  return true;
}

// Tabs
function activateTab(id) {
  $$(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === id));
  $$(".panel").forEach(p => p.classList.toggle("active", p.id === `tab-${id}`));
  const sel = $("#tabsMobile");
  if (sel && sel.value !== id) sel.value = id;
  if (id === "components") renderComponents();
  if (id === "coverage") renderCoverage();
  if (id === "graph") renderGraph();
  if (id === "export") renderExport();
  if (id === "threats" || id === "gaps") renderThreats();
}
$$(".tab").forEach(btn => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));
$("#tabsMobile")?.addEventListener("change", e => activateTab(e.target.value));

// --- Setup tab ---
$("#loadBtn").addEventListener("click", async () => {
  const domain = $("#domainSelect").value;
  const url = $("#sourceUrl").value.trim() || undefined;
  await runLoad({ domain, url, force: true });
});
$("#clearCacheBtn").addEventListener("click", async () => {
  await clearAttackCache();
  setStatus("Cache cleared", "ok");
});
$("#stixFile").addEventListener("change", async ev => {
  const file = ev.target.files?.[0];
  if (!file) return;
  setStatus(`Reading ${file.name}…`, "busy");
  try {
    const text = await file.text();
    const bundle = JSON.parse(text);
    state.attack = loadAttackFromBundle(bundle, { domain: $("#domainSelect").value });
    onAttackLoaded("file");
  } catch (e) {
    console.error(e);
    setStatus(`Failed to read file: ${e.message}`, "error");
  } finally {
    ev.target.value = "";
  }
});

async function runLoad({ domain, url, force }) {
  setStatus("Loading ATT&CK…", "busy");
  try {
    state.attack = await loadAttack({ domain, url, force, onProgress: p => setStatus(p.message, "busy") });
    onAttackLoaded(state.attack.meta.source);
  } catch (e) {
    console.error("MITRE CTI fetch failed", e);
    setStatus(`MITRE CTI fetch failed: ${e.message}. Falling back to bundled offline ATT&CK.`, "error");
    setBanner(
      `<strong>Network fetch from github.com/mitre/cti failed.</strong> ` +
      `Your browser couldn't reach the MITRE CTI feed (corporate proxy, TLS interception, or offline). ` +
      `Falling back to the bundled offline ATT&CK (38 data sources, 38 representative techniques, 20 groups). ` +
      `Use this for the workflow demo, or upload a local STIX file on the MITRE CTI tab.`,
      "warn"
    );
    try {
      state.attack = await loadOfflineBundle();
      onAttackLoaded("offline-bundle");
    } catch (e2) {
      setStatus(`Both online and offline ATT&CK failed: ${e2.message}`, "error");
      setBanner(`<strong>Couldn't load any ATT&CK data:</strong> ${escapeHtml(e2.message)}`, "error");
    }
  }
}

function onAttackLoaded(source) {
  const a = state.attack;
  setStatus(`Loaded ${a.dataSources.length} data sources, ${a.techniques.length} techniques, ${a.groups?.length || 0} groups (${source})`, "ok");
  renderSetupSummary();
  populatePlatformFilter();
  populateTacticFilter();
  populateGroupSelectors();
  refreshAll();
  // Auto-show inventory tab once data is loaded
  if ($(".tab.active").dataset.tab === "setup") {
    $$(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === "inventory"));
    $$(".panel").forEach(p => p.classList.toggle("active", p.id === "tab-inventory"));
  }
}

function renderSetupSummary() {
  const a = state.attack;
  if (!a) { $("#setupSummary").innerHTML = ""; return; }
  $("#setupSummary").innerHTML = `
    <div class="grid">
      <div class="stat"><span class="label">Domain</span><span class="value">${escapeHtml(a.meta.domain)}</span></div>
      <div class="stat"><span class="label">Version</span><span class="value">${escapeHtml(String(a.meta.version))}</span></div>
      <div class="stat"><span class="label">Data sources</span><span class="value">${a.dataSources.length}</span></div>
      <div class="stat"><span class="label">Data components</span><span class="value">${a.dataComponents.length}</span></div>
      <div class="stat"><span class="label">Techniques</span><span class="value">${a.techniques.length}</span></div>
      <div class="stat"><span class="label">Loaded</span><span class="value">${escapeHtml(a.meta.fetchedAt || "")}</span></div>
    </div>
  `;
}

function populatePlatformFilter() {
  const sel = $("#platformFilter");
  sel.innerHTML = `<option value="">All platforms</option>` +
    state.attack.platforms.map(p => `<option value="${escapeAttr(p)}">${escapeHtml(p)}</option>`).join("");
}

function populateTacticFilter() {
  const sel = $("#tacticFilter");
  sel.innerHTML = `<option value="">All tactics</option>` +
    state.attack.tactics.map(t => `<option value="${escapeAttr(t.shortname)}">${escapeHtml(t.name)}</option>`).join("");
}

// --- Inventory tab ---
$("#dsFilter").addEventListener("input", e => { state.filters.ds = e.target.value.toLowerCase(); renderInventory(); });
$("#platformFilter").addEventListener("change", e => { state.filters.platform = e.target.value; renderInventory(); });
$("#onlyScored")?.addEventListener("change", e => { state.filters.onlyScored = e.target.checked; renderInventory(); });
$("#componentFilter")?.addEventListener("input", e => { state.filters.component = e.target.value.toLowerCase(); renderComponents(); });
$("#componentScoreFilter")?.addEventListener("change", e => { state.filters.componentScore = e.target.value; renderComponents(); });
$("#setAllBtn").addEventListener("click", () => {
  if (!state.attack) { setStatus("Load ATT&CK first", "error"); return; }
  const score = Number($("#setAllValue").value);
  setAllSources(state.inventory, state.attack, score);
  saveInventory(state.inventory);
  refreshAll();
});
$("#resetInventoryBtn").addEventListener("click", () => {
  if (!confirm("Reset the entire inventory?")) return;
  state.inventory = resetInventory();
  refreshAll();
});
$("#inventoryFile").addEventListener("change", async ev => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const looksJson = /\.json$/i.test(file.name) || /^\s*[\[{]/.test(text);
    if (!looksJson && typeof window.jsyaml === "undefined") {
      throw new Error("YAML library failed to load. The bundled vendor/js-yaml.min.js is missing or blocked. Try a JSON inventory file instead, or reload the page.");
    }
    state.inventory = looksJson ? importJson(text) : importYaml(text);
    saveInventory(state.inventory);

    // If ATT&CK isn't loaded yet, the rows can't be displayed. Auto-load the
    // bundled offline ATT&CK so the import is immediately visible — this is
    // exactly the case where users were getting "17 entries imported" but
    // seeing no rows because the network fetch had silently failed.
    if (!state.attack) {
      setStatus("ATT&CK not loaded — using bundled offline ATT&CK so the import is visible…", "busy");
      try {
        state.attack = await loadOfflineBundle();
        onAttackLoaded("offline-bundle");
      } catch (e2) {
        setBanner(`Inventory was saved, but the bundled ATT&CK failed to load (${escapeHtml(e2.message)}). Reload the page or upload a STIX bundle on tab 1.`, "error");
      }
    }

    const counts = inventoryStats(state.inventory);
    refreshAll();
    if (counts.sources === 0) {
      setStatus(`Imported ${file.name} but it had no data sources`, "error");
    } else {
      setStatus(`Imported ${file.name}: ${counts.sources} sources, ${counts.overrides} component overrides`, "ok");
      setBanner(`Imported <strong>${escapeHtml(file.name)}</strong>: ${counts.sources} data sources, ${counts.overrides} component overrides. Switch to <a href="#" data-goto="components">Data Components</a> or <a href="#" data-goto="coverage">Detection Strategies</a> to see the impact.`, "ok");
      $("#globalBanner")?.querySelectorAll('[data-goto]').forEach(a => a.addEventListener("click", e => { e.preventDefault(); activateTab(a.dataset.goto); }));
    }
  } catch (e) {
    console.error("Import failed", e);
    setStatus(`Import failed: ${e.message}`, "error");
    setBanner(`<strong>Import failed:</strong> ${escapeHtml(e.message)}`, "error");
  } finally {
    ev.target.value = ""; // allow re-selecting the same file
  }
});

function inventoryStats(inv) {
  const sources = (inv.data_sources || []).length;
  const overrides = (inv.data_sources || []).reduce((n, e) => n + (e.data_source?.length || 0), 0);
  return { sources, overrides };
}
$("#exportInventoryYaml").addEventListener("click", () => {
  downloadText(exportYaml(state.inventory), "inventory.yaml", "text/yaml");
});
$("#exportInventoryJson").addEventListener("click", () => {
  downloadText(exportJson(state.inventory), "inventory.json", "application/json");
});

function renderInventory() {
  const root = $("#inventoryTable");
  const summary = $("#inventorySummary");
  if (!state.attack) {
    if (root) root.innerHTML = `<div style="padding:20px;color:var(--muted)">Load MITRE CTI data first (tab 1).</div>`;
    if (summary) summary.innerHTML = "";
    return;
  }
  const filterText = state.filters.ds;
  const filterPlatform = state.filters.platform;
  const onlyScored = !!state.filters.onlyScored;

  const compScores = effectiveComponentScores(state.inventory, state.attack);

  // Inventory summary across the WHOLE attack model (not affected by filters)
  const totalSources = state.attack.dataSources.length;
  const scoredSources = state.attack.dataSources.filter(ds => getSourceScore(ds) > 0).length;
  const totalComps = state.attack.dataComponents.length;
  const scoredComps = Array.from(compScores.values()).filter(v => v.score > 0).length;
  if (summary) {
    summary.className = "inv-summary" + (scoredSources > 0 ? " populated" : "");
    summary.innerHTML = `
      <div class="pill"><strong>${scoredSources} / ${totalSources}</strong>data sources scored</div>
      <div class="pill"><strong>${scoredComps} / ${totalComps}</strong>data components covered</div>
      <div class="pill"><strong>${state.inventory.data_sources?.length || 0}</strong>entries in saved inventory</div>
      <div class="pill"><strong>${state.inventory.name || "Default"}</strong>inventory name</div>
    `;
  }

  const sources = state.attack.dataSources.filter(ds => {
    if (filterText && !(ds.name.toLowerCase().includes(filterText) || ds.attackId?.toLowerCase().includes(filterText))) return false;
    if (filterPlatform && !ds.platforms.includes(filterPlatform)) return false;
    if (onlyScored && getSourceScore(ds) === 0 && !ds.components.some(c => (compScores.get(c.id)?.score || 0) > 0)) return false;
    return true;
  });

  let html = `<div class="ds-row header">
    <div></div><div>Data source</div><div>Components</div><div>Score</div>
  </div>`;

  for (const ds of sources) {
    const expanded = state.expanded.has(ds.id);
    const score = getSourceScore(ds);
    const compCount = ds.components.length;
    const coveredComp = ds.components.filter(c => (compScores.get(c.id)?.score || 0) > 0).length;
    html += `
      <div class="ds-row" data-ds-id="${escapeAttr(ds.id)}">
        <div class="toggle" data-toggle="${escapeAttr(ds.id)}">${expanded ? "▾" : "▸"}</div>
        <div>
          <div class="ds-name">${escapeHtml(ds.name)} <span style="color:var(--muted);font-weight:400">${escapeHtml(ds.attackId || "")}</span></div>
          <div class="ds-meta">${escapeHtml(ds.platforms.join(", ") || "—")} · ${coveredComp}/${compCount} components scored</div>
        </div>
        <div class="ds-meta">${compCount} component${compCount === 1 ? "" : "s"}</div>
        <div>${scoreSelect(score, "ds", ds.name)}</div>
      </div>
      <div class="ds-components ${expanded ? "open" : ""}" data-components-for="${escapeAttr(ds.id)}">
        ${ds.components.map(dc => {
          const eff = compScores.get(dc.id);
          const dcScore = eff?.score ?? score;
          const techCount = dc.techniqueIds.length;
          return `<div class="dc-row">
            <div>
              <div class="dc-name">${escapeHtml(dc.name)}</div>
              <div class="dc-meta">${techCount} technique${techCount === 1 ? "" : "s"} detected</div>
            </div>
            <div class="dc-meta">${eff?.hasOverride ? "(override)" : "(inherits)"}</div>
            <div>${scoreSelect(dcScore, "dc", `${ds.name}|${dc.name}`)}</div>
          </div>`;
        }).join("") || `<div class="dc-meta">No components defined.</div>`}
      </div>
    `;
  }

  root.innerHTML = html;

  root.querySelectorAll("[data-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-toggle");
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      renderInventory();
    });
  });

  root.querySelectorAll("select[data-kind]").forEach(sel => {
    sel.addEventListener("change", () => {
      const kind = sel.dataset.kind;
      const key = sel.dataset.key;
      const value = Number(sel.value);
      if (kind === "ds") {
        setSourceScore(state.inventory, key, value, { cascade: true });
      } else {
        const [src, comp] = key.split("|");
        setComponentScore(state.inventory, src, comp, value);
      }
      saveInventory(state.inventory);
      refreshAll();
    });
  });
}

// --- Data Components tab ---
function renderComponents() {
  const root = $("#componentTable");
  const stats = $("#componentStats");
  if (!root) return;
  if (!state.attack) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">Load MITRE CTI data first (tab 1).</div>`;
    if (stats) stats.innerHTML = "";
    return;
  }
  const compScores = effectiveComponentScores(state.inventory, state.attack);
  const filter = state.filters.component;
  const minScore = state.filters.componentScore;
  const all = state.attack.dataComponents.map(dc => {
    const eff = compScores.get(dc.id);
    const score = eff?.score ?? 0;
    return {
      id: dc.id,
      name: dc.name,
      sourceName: state.attack.dataSourceById.get(dc.sourceId)?.name || "?",
      score,
      hasOverride: !!eff?.hasOverride,
      techCount: dc.techniqueIds.length,
    };
  });
  const total = all.length;
  const covered = all.filter(c => c.score > 0).length;
  const good = all.filter(c => c.score >= 3).length;
  if (stats) {
    stats.innerHTML = `
      <div class="stat-card"><div class="label">Total components</div><div class="value">${total}</div></div>
      <div class="stat-card"><div class="label">Covered (score &gt; 0)</div><div class="value">${covered}</div><div class="sub">${pct(covered/Math.max(total,1))}</div></div>
      <div class="stat-card"><div class="label">Good (score &ge; 3)</div><div class="value">${good}</div></div>
      <div class="stat-card"><div class="label">Uncovered</div><div class="value" style="color:var(--bad)">${total - covered}</div></div>
    `;
  }
  const rows = all.filter(c => {
    if (filter && !(c.name.toLowerCase().includes(filter) || c.sourceName.toLowerCase().includes(filter))) return false;
    if (minScore === "0" && c.score !== 0) return false;
    if (minScore === "1" && c.score < 1) return false;
    if (minScore === "3" && c.score < 3) return false;
    return true;
  }).sort((a, b) => b.score - a.score || a.sourceName.localeCompare(b.sourceName) || a.name.localeCompare(b.name));

  let html = `<div class="tech-row header"><div>Component</div><div>Data source</div><div>Techniques</div><div></div><div>Score</div></div>`;
  for (const c of rows.slice(0, 1500)) {
    html += `
      <div class="tech-row">
        <div><strong>${escapeHtml(c.name)}</strong></div>
        <div style="color:var(--muted)">${escapeHtml(c.sourceName)}</div>
        <div style="color:var(--muted);font-size:11px">${c.techCount} tech</div>
        <div style="color:var(--muted);font-size:11px">${c.hasOverride ? "override" : ""}</div>
        <div><span class="score-badge s${c.score}">${c.score}</span></div>
      </div>
    `;
  }
  root.innerHTML = html;
}

function scoreSelect(score, kind, key) {
  const opts = [0, 1, 2, 3, 4, 5].map(v => `<option value="${v}" ${v === score ? "selected" : ""}>${v} ${["None","Poor","Fair","Good","Very good","Excellent"][v]}</option>`).join("");
  return `<select data-kind="${escapeAttr(kind)}" data-key="${escapeAttr(key)}">${opts}</select>`;
}

function getSourceScore(ds) {
  const entry = (state.inventory.data_sources || []).find(e => e.data_source_name?.toLowerCase() === ds.name.toLowerCase());
  return entry ? Number(entry.score) || 0 : 0;
}

// --- Coverage tab ---
$("#techFilter").addEventListener("input", e => { state.filters.tech = e.target.value.toLowerCase(); renderCoverage(); });
$("#tacticFilter").addEventListener("change", e => { state.filters.tactic = e.target.value; renderCoverage(); });
$("#coverageFilter").addEventListener("change", e => { state.filters.coverage = e.target.value; renderCoverage(); });

function renderCoverage() {
  const root = $("#techniqueTable");
  const stats = $("#coverageStats");
  if (!state.attack) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">Load ATT&amp;CK data first.</div>`;
    stats.innerHTML = "";
    return;
  }
  const compScores = effectiveComponentScores(state.inventory, state.attack);
  const cov = computeCoverage(state.attack, compScores);

  stats.innerHTML = `
    <div class="stat-card"><div class="label">Techniques (total)</div><div class="value">${cov.summary.total}</div></div>
    <div class="stat-card"><div class="label">Detectable</div><div class="value">${cov.summary.detectable}</div><div class="sub">have data-component detections</div></div>
    <div class="stat-card"><div class="label">Covered</div><div class="value">${cov.summary.covered}</div><div class="sub">${pct(cov.summary.covered / Math.max(cov.summary.detectable,1))} of detectable</div></div>
    <div class="stat-card"><div class="label">Fully covered</div><div class="value">${cov.summary.fully}</div></div>
    <div class="stat-card"><div class="label">Partial</div><div class="value">${cov.summary.partial}</div></div>
    <div class="stat-card"><div class="label">Avg score (covered)</div><div class="value">${cov.summary.avgScore.toFixed(2)}</div></div>
  `;

  const ft = state.filters.tech;
  const fTactic = state.filters.tactic;
  const fCov = state.filters.coverage;

  const rows = cov.rows.filter(r => {
    if (!r.hasDetections && fCov !== "uncovered" && !fCov) {
      // hide non-detectable techniques by default for clarity
      return false;
    }
    if (ft) {
      const hay = `${r.attackId} ${r.name} ${r.tactics.join(" ")}`.toLowerCase();
      if (!hay.includes(ft)) return false;
    }
    if (fTactic && !r.tactics.includes(fTactic)) return false;
    if (fCov === "covered" && r.weightedScore <= 0) return false;
    if (fCov === "partial" && !(r.ratio > 0 && r.ratio < 1)) return false;
    if (fCov === "full" && r.ratio < 1) return false;
    if (fCov === "uncovered" && r.weightedScore > 0) return false;
    return true;
  });

  let html = `<div class="tech-row header">
    <div>ID</div><div>Technique</div><div>Tactics</div><div>Coverage</div><div>Score</div>
  </div>`;
  for (const r of rows.slice(0, 1500)) {
    const fillPct = Math.round(r.ratio * 100);
    html += `
      <div class="tech-row" title="${escapeAttr(`${r.coveredComponents}/${r.totalDetectingComponents} detecting components covered`)}">
        <div class="tech-id">${escapeHtml(r.attackId)}</div>
        <div>${escapeHtml(r.name)}${r.isSubtechnique ? ' <span style="color:var(--muted);font-size:11px">sub</span>' : ""}</div>
        <div class="tech-tactics">${escapeHtml(r.tactics.join(", "))}</div>
        <div>
          <div class="coverage-bar"><div class="fill" style="width:${fillPct}%"></div></div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">${r.coveredComponents}/${r.totalDetectingComponents} (${fillPct}%)</div>
        </div>
        <div><span class="score-badge s${Math.round(r.weightedScore)}">${r.weightedScore.toFixed(2)}</span></div>
      </div>
    `;
  }
  if (rows.length > 1500) {
    html += `<div class="tech-row"><div></div><div style="color:var(--muted)">Showing first 1500 of ${rows.length} matches; refine filters.</div><div></div><div></div><div></div></div>`;
  }
  root.innerHTML = html;
}

// --- Threats tab ---
$("#groupFilter").addEventListener("input", e => { state.filters.group = e.target.value.toLowerCase(); renderThreats(); });
$("#clearGroupSel").addEventListener("click", () => {
  state.threats = clearSelection(state.threats);
  saveThreats(state.threats);
  refreshAll();
});
$("#groupsFile").addEventListener("change", async ev => {
  const file = ev.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    if (typeof window.jsyaml === "undefined") throw new Error("YAML library not loaded yet — reload the page");
    const looksJson = /\.json$/i.test(file.name) || /^\s*[\[{]/.test(text);
    state.threats = looksJson ? importThreatsJson(text) : importThreatsYaml(text);
    saveThreats(state.threats);
    refreshAll();
    setStatus(`Imported ${state.threats.groups.length} groups from ${file.name}`, "ok");
  } catch (e) {
    console.error("Group import failed", e);
    setStatus(`Group import failed: ${e.message}`, "error");
  } finally {
    ev.target.value = "";
  }
});
$("#exportGroupsYaml").addEventListener("click", () => {
  downloadText(exportThreatsYaml(state.threats), "groups.yaml", "text/yaml");
});
$("#threatStatusFilter").addEventListener("change", e => { state.filters.threatStatus = e.target.value; renderGapAnalysis(); });

$("#downloadThreatLayer").addEventListener("click", () => downloadThreatLayer("groups"));
$("#downloadGapLayer").addEventListener("click", () => downloadThreatLayer("gaps"));
$("#downloadDetectionsLayer")?.addEventListener("click", () => {
  if (!state.attack) { setStatus("Load ATT&CK first", "error"); return; }
  const layer = currentLayer();
  if (!layer) return;
  downloadText(JSON.stringify(layer, null, 2), `${slug(layer.name)}.json`, "application/json");
});

function downloadThreatLayer(mode) {
  if (!state.attack) { setStatus("Load ATT&CK first", "error"); return; }
  const cov = computeCoverage(state.attack, effectiveComponentScores(state.inventory, state.attack));
  const rowsByStix = new Map(cov.rows.map(r => [r.stixId, r]));
  const layer = buildThreatLayer({ attack: state.attack, threats: state.threats, mode, coverageRowsByStixId: rowsByStix });
  if (!layer) { setStatus("Select at least one group first", "error"); return; }
  downloadText(JSON.stringify(layer, null, 2), `${slug(layer.name)}.json`, "application/json");
}

function populateGroupSelectors() {
  // Nothing fancy; renderThreats does the list.
}

function renderThreats() {
  const listRoot = $("#groupList");
  const pickerStats = $("#threatPickerStats");
  if (!state.attack) {
    if (listRoot) listRoot.innerHTML = `<div style="padding:20px;color:var(--muted)">Load ATT&CK data first.</div>`;
    if (pickerStats) pickerStats.innerHTML = "";
    renderGapAnalysis();
    return;
  }

  // Build group list with selection state
  const filter = state.filters.group;
  const filtered = state.attack.groups.filter(g => {
    if (!filter) return true;
    const hay = [g.attackId, g.name, ...(g.aliases || [])].join(" ").toLowerCase();
    return hay.includes(filter);
  });
  const selectedCount = (state.threats.groups || []).filter(g => g.enabled).length;

  if (pickerStats) {
    pickerStats.innerHTML = `
      <div class="stat-card"><div class="label">Available groups</div><div class="value">${state.attack.groups.length}</div></div>
      <div class="stat-card"><div class="label">Selected</div><div class="value">${selectedCount}</div><div class="sub">switch to Gap Analysis to see results</div></div>
    `;
  }

  let html = `<div class="group-row header"><div></div><div>Group</div><div>ID</div><div>Techniques</div></div>`;
  for (const g of filtered.slice(0, 1000)) {
    const sel = isGroupSelected(state.threats, g);
    const aliases = g.aliases.length ? `<div class="aliases">a.k.a. ${escapeHtml(g.aliases.slice(0, 3).join(", "))}${g.aliases.length > 3 ? ", …" : ""}</div>` : "";
    html += `
      <label class="group-row ${sel ? "selected" : ""}">
        <input type="checkbox" data-gid="${escapeAttr(g.id)}" ${sel ? "checked" : ""} />
        <div><div class="name">${escapeHtml(g.name)}</div>${aliases}</div>
        <div class="tech-id">${escapeHtml(g.attackId)}</div>
        <div style="color:var(--muted)">${g.techniqueIds.length} techniques</div>
      </label>
    `;
  }
  if (filtered.length > 1000) {
    html += `<div class="group-row"><div></div><div style="color:var(--muted)">Showing first 1000 of ${filtered.length} groups; refine filter.</div><div></div><div></div></div>`;
  }
  listRoot.innerHTML = html;
  listRoot.querySelectorAll('input[type=checkbox][data-gid]').forEach(cb => {
    cb.addEventListener("change", () => {
      const gid = cb.dataset.gid;
      const group = state.attack.groupById.get(gid);
      state.threats = setGroupSelected(state.threats, group, cb.checked);
      saveThreats(state.threats);
      cb.closest(".group-row").classList.toggle("selected", cb.checked);
      // Update picker stats and gap analysis without rebuilding the whole list
      const newCount = (state.threats.groups || []).filter(g => g.enabled).length;
      if (pickerStats) {
        pickerStats.querySelectorAll(".stat-card .value")[1].textContent = newCount;
      }
      renderGapAnalysis();
    });
  });

  renderGapAnalysis();
}

function renderGapAnalysis() {
  const tableRoot = $("#threatTable");
  const statsRoot = $("#threatStats");
  if (!state.attack) return;
  const cov = computeCoverage(state.attack, effectiveComponentScores(state.inventory, state.attack));
  const rowsByStix = new Map(cov.rows.map(r => [r.stixId, r]));
  const gap = gapAnalysis(state.threats, state.attack, rowsByStix);

  if (!gap.groups.length) {
    statsRoot.innerHTML = `<div class="stat-card"><div class="label">No groups selected</div><div class="value">—</div><div class="sub">Pick groups above to see gaps</div></div>`;
    tableRoot.innerHTML = "";
    return;
  }

  statsRoot.innerHTML = `
    <div class="stat-card"><div class="label">Selected groups</div><div class="value">${gap.groups.length}</div><div class="sub">${escapeHtml(gap.groups.slice(0, 4).map(g => g.attackId).join(", "))}${gap.groups.length > 4 ? "…" : ""}</div></div>
    <div class="stat-card"><div class="label">Threat techniques</div><div class="value">${gap.summary.totalThreats}</div></div>
    <div class="stat-card"><div class="label">Covered</div><div class="value">${gap.summary.covered}</div></div>
    <div class="stat-card"><div class="label">Partial</div><div class="value">${gap.summary.partial}</div></div>
    <div class="stat-card"><div class="label">Gaps</div><div class="value" style="color:var(--bad)">${gap.summary.gaps}</div><div class="sub">no coverage</div></div>
    <div class="stat-card"><div class="label">Undetectable</div><div class="value" style="color:var(--warn)">${gap.summary.undetectable}</div><div class="sub">no detections defined</div></div>
  `;

  const fStatus = state.filters.threatStatus;
  const rows = gap.threatTechniques.filter(r => !fStatus || r.status === fStatus);

  let html = `<div class="tech-row header"><div>ID</div><div>Technique</div><div>Tactics</div><div>Status</div><div>Score</div></div>`;
  for (const r of rows.slice(0, 1500)) {
    const tech = r.tech;
    const groupBadge = `<span style="color:var(--muted);font-size:11px"> · ${r.groupCount} group${r.groupCount === 1 ? "" : "s"}</span>`;
    html += `
      <div class="tech-row" title="${escapeAttr(`Used by ${r.groups.map(g => g.attackId).join(", ")}`)}">
        <div class="tech-id">${escapeHtml(tech.attackId)}</div>
        <div>${escapeHtml(tech.name)}${groupBadge}</div>
        <div class="tech-tactics">${escapeHtml(tech.tactics.join(", "))}</div>
        <div><span class="score-badge ${statusClass(r.status)}">${escapeHtml(statusLabel(r.status))}</span></div>
        <div><span class="score-badge s${Math.round(r.weightedScore)}">${r.weightedScore.toFixed(2)}</span></div>
      </div>
    `;
  }
  if (rows.length > 1500) {
    html += `<div class="tech-row"><div></div><div style="color:var(--muted)">Showing first 1500 of ${rows.length}; refine filters.</div><div></div><div></div><div></div></div>`;
  }
  tableRoot.innerHTML = html;
}

function statusClass(s) { return ({ gap: "s1", undetectable: "s2", partial: "s3", covered: "s5" })[s] || "s0"; }
function statusLabel(s) { return ({ gap: "GAP", undetectable: "no-detect", partial: "partial", covered: "covered" })[s] || s; }

// --- Relationships (mermaid) tab ---
$("#graphSourceSelect").addEventListener("change", e => { state.graph.sourceId = e.target.value; renderGraph(); });
$("#graphMaxTech").addEventListener("change", e => { state.graph.maxTech = Math.max(1, Number(e.target.value) || 20); renderGraph(); });
$("#graphOnlyCovered").addEventListener("change", e => { state.graph.onlyCovered = e.target.checked; renderGraph(); });
$("#graphTechSearch").addEventListener("change", e => {
  if (!state.attack) return;
  const v = e.target.value.trim();
  // Match by attackId first, then by exact name from the datalist
  const tech = state.attack.techniqueByAttackId.get(v) ||
               state.attack.techniques.find(t => `${t.attackId} — ${t.name}` === v) ||
               state.attack.techniques.find(t => t.name.toLowerCase() === v.toLowerCase());
  state.graph.techStixId = tech ? tech.id : "";
  renderGraph();
});

function ensureMermaid() {
  if (state.mermaidReady || !window.mermaid) return state.mermaidReady;
  window.mermaid.initialize({
    startOnLoad: false,
    theme: "dark",
    securityLevel: "loose",
    flowchart: { htmlLabels: true, curve: "basis" },
    themeVariables: {
      background: "#161b22",
      primaryColor: "#1c2230",
      primaryTextColor: "#e6edf3",
      primaryBorderColor: "#30363d",
      lineColor: "#475569",
      fontFamily: "ui-sans-serif, system-ui",
    },
  });
  state.mermaidReady = true;
  return true;
}

async function renderMermaidInto(host, source) {
  if (!source) {
    host.innerHTML = `<div class="mermaid-empty">Nothing to draw yet.</div>`;
    return;
  }
  if (!ensureMermaid()) {
    host.innerHTML = `<div class="mermaid-empty">Mermaid loading…</div>`;
    return;
  }
  const id = `mmd-${++state.mermaidSeq}`;
  try {
    const { svg } = await window.mermaid.render(id, source);
    host.innerHTML = svg;
  } catch (e) {
    console.error("Mermaid render failed", e, source);
    host.innerHTML = `<div class="mermaid-error">Mermaid render failed:\n${escapeHtml(e?.message || String(e))}</div><pre class="preview">${escapeHtml(source)}</pre>`;
  }
}

function renderGraph() {
  const conceptualHost = $("#diagramConceptual");
  const sourceHost = $("#diagramSource");
  const techHost = $("#diagramTechnique");
  const overviewHost = $("#diagramOverview");

  // Conceptual is always renderable
  renderMermaidInto(conceptualHost, conceptualDiagram());

  if (!state.attack) {
    sourceHost.innerHTML = `<div class="mermaid-empty">Load ATT&CK data first.</div>`;
    techHost.innerHTML = `<div class="mermaid-empty">Load ATT&CK data first.</div>`;
    overviewHost.innerHTML = `<div class="mermaid-empty">Load ATT&CK data first.</div>`;
    return;
  }

  // Populate selectors lazily
  populateGraphSelectors();

  const compScores = effectiveComponentScores(state.inventory, state.attack);

  // Source -> components -> techniques
  const ds = state.attack.dataSourceById.get(state.graph.sourceId);
  if (ds) {
    const src = sourceDiagram({
      dataSource: ds,
      attack: state.attack,
      componentScores: compScores,
      maxTechniquesPerComponent: state.graph.maxTech,
      onlyCovered: state.graph.onlyCovered,
    });
    renderMermaidInto(sourceHost, src);
  } else {
    sourceHost.innerHTML = `<div class="mermaid-empty">Pick a data source above.</div>`;
  }

  // Technique -> components
  const tech = state.attack.techniqueById.get(state.graph.techStixId);
  if (tech) {
    renderMermaidInto(techHost, techniqueDiagram({ technique: tech, attack: state.attack, componentScores: compScores }));
  } else {
    techHost.innerHTML = `<div class="mermaid-empty">Search for a technique above (e.g. "T1059" or "PowerShell").</div>`;
  }

  // Coverage overview
  renderMermaidInto(overviewHost, overviewDiagram({ attack: state.attack, componentScores: compScores }) || "");
}

function populateGraphSelectors() {
  const sel = $("#graphSourceSelect");
  if (sel.options.length <= 1 && state.attack) {
    sel.innerHTML = `<option value="">Select a data source…</option>` +
      state.attack.dataSources.map(ds => `<option value="${escapeAttr(ds.id)}">${escapeHtml(ds.name)} (${escapeHtml(ds.attackId || "")})</option>`).join("");
  }
  if (state.graph.sourceId) sel.value = state.graph.sourceId;

  const list = $("#graphTechList");
  if (list.children.length === 0 && state.attack) {
    list.innerHTML = state.attack.techniques
      .map(t => `<option value="${escapeAttr(`${t.attackId} — ${t.name}`)}">`)
      .join("");
  }
}

// --- Export tab ---
$("#downloadLayerBtn").addEventListener("click", () => {
  const layer = currentLayer();
  if (!layer) return;
  downloadText(JSON.stringify(layer, null, 2), `${slug(layer.name)}.json`, "application/json");
});
$("#copyLayerBtn").addEventListener("click", async () => {
  const layer = currentLayer();
  if (!layer) return;
  await navigator.clipboard.writeText(JSON.stringify(layer, null, 2));
  setStatus("Layer JSON copied to clipboard", "ok");
});
["#layerName", "#layerDesc", "#colorMin", "#colorMax", "#includeUncovered"].forEach(s => {
  $(s).addEventListener("input", renderExport);
  $(s).addEventListener("change", renderExport);
});

function currentLayer() {
  if (!state.attack) { setStatus("Load ATT&CK first", "error"); return null; }
  const compScores = effectiveComponentScores(state.inventory, state.attack);
  const cov = computeCoverage(state.attack, compScores);
  return buildNavigatorLayer({
    coverage: cov,
    attack: state.attack,
    name: $("#layerName").value || "Data source coverage",
    description: $("#layerDesc").value || "",
    colorMin: $("#colorMin").value,
    colorMax: $("#colorMax").value,
    includeUncovered: $("#includeUncovered").checked,
  });
}

function renderExport() {
  const layer = currentLayer();
  if (!layer) { $("#layerPreview").textContent = ""; return; }
  $("#layerPreview").textContent = JSON.stringify(layer, null, 2);
}

// --- helpers ---
function downloadText(text, filename, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function escapeAttr(s) { return escapeHtml(s); }
function slug(s) { return String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function pct(n) { return `${Math.round((n || 0) * 100)}%`; }

// --- init ---
(async () => {
  checkVendorLibs();
  // Prefer cached real ATT&CK if available; otherwise auto-load the
  // bundled offline ATT&CK so the app is usable on the first visit
  // without depending on github.com being reachable.
  try {
    setStatus("Checking cache…", "busy");
    state.attack = await loadAttack({ domain: "enterprise-attack", cacheOnly: true });
    onAttackLoaded("cache");
  } catch (e) {
    if (e.code === "NO_CACHE") {
      try {
        setStatus("Loading bundled offline ATT&CK…", "busy");
        state.attack = await loadOfflineBundle();
        onAttackLoaded("offline-bundle");
        setBanner(
          `Loaded the <strong>bundled offline ATT&CK</strong> (38 data sources, 38 representative techniques, 20 groups). ` +
          `Click <em>Load / Refresh</em> on tab 1 (<em>MITRE CTI Data</em>) to upgrade to the live MITRE feed.`,
          "warn"
        );
      } catch (e2) {
        setStatus(`Couldn't load bundled ATT&CK: ${e2.message}`, "error");
      }
    } else {
      setStatus(`Cache check failed: ${e.message}`, "error");
    }
  }
  refreshAll();
})();
