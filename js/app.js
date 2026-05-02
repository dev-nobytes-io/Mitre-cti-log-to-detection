import { loadAttack, loadAttackFromBundle, clearAttackCache, loadOfflineBundle } from "./attack.js";
import {
  loadInventory, saveInventory, resetInventory,
  effectiveComponentScores, setSourceScore, setComponentScore, setAllSources,
  effectiveLogSourceScores, setLogSourceScore, setAllLogSources, removeLogSource,
  setLogSourceEnabled, setLogSourceComponentRefs,
  setStrategyEnabled, isStrategyEnabled,
  setStrategyManuallyCovered, isStrategyManuallyCovered,
  setRiskAccepted, isRiskAccepted, logSourceRiskKey,
  exportYaml, importYaml, exportJson, importJson,
} from "./inventory.js";
import { computeCoverage } from "./coverage.js";
import { buildNavigatorLayer } from "./navigator.js";
import { conceptualDiagram, sourceDiagram, techniqueDiagram, overviewDiagram, logSourceCascadeDiagram } from "./diagrams.js";
import {
  loadThreats, saveThreats, resetThreats,
  isGroupSelected, setGroupSelected, clearSelection,
  selectedGroups, gapAnalysis, buildThreatLayer,
  exportThreatsYaml, importThreatsYaml, importThreatsJson,
} from "./threats.js";

// Refactor-merge chunk 2: feature flag for the unified Log Inventory panel.
// Reads ?merged=1 from the URL or localStorage.MERGED_INVENTORY=1. While
// the flag is on, activateTab("inventory") routes to #tab-inventory-v2
// instead of the legacy panel. Old tabs 2/3/4 stay default-on so the
// scaffold ships without disturbing the live UI.
function readMergedInventoryFlag() {
  try {
    const urlFlag = new URLSearchParams(location.search).get("merged");
    if (urlFlag === "1" || urlFlag === "true") return true;
    if (urlFlag === "0" || urlFlag === "false") return false;
    return localStorage.getItem("MERGED_INVENTORY") === "1";
  } catch (_) { return false; }
}

const state = {
  attack: null,
  inventory: loadInventory(),
  threats: loadThreats(),
  mergedInventory: readMergedInventoryFlag(),
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
    analyticAggregation: "min", // how to aggregate log-source scores into an analytic score (V2 chain)
    inventoryGrouping: "component", // chunk N: 'component' is the merged Data Component → Log Source → Channel hierarchy (default); 'name' groups every channel under its log-source name (alternate view)
    customLsCompFilter: "", // chunk 13: filter for the component picker on the manual-entry form
    mergedInvFilter: "", // refactor-merge chunk 3: filter for the merged inventory hierarchy
  },
  // chunk 13: which data components the user has selected for the
  // custom log source they're about to add. Persists across opens of
  // the form until Add fires (then it clears). Stored as a Set of
  // STIX component ids.
  customLsComponentRefs: new Set(),
  expanded: new Set(),
  // chunk N: track whether the inventory tab has run its one-shot
  // auto-expand pass. Auto-expand fires once per inventory replacement
  // (boot, import, reset) to surface scored groups without an extra
  // click; after that the user controls expansion.
  inventoryAutoExpandDone: false,
  graph: {
    sourceId: "",
    techStixId: "",
    maxTech: 20,
    onlyCovered: false,
    // chunk 8: log-source cascade picker
    selectedLogSources: new Set(), // Set<logSourceId>
    logSourceFilter: "",
  },
  mermaidReady: false,
  mermaidSeq: 0,
};

const $ = sel => document.querySelector(sel);
const $$ = sel => Array.from(document.querySelectorAll(sel));

// Trailing-edge debounce. Used on the inventory filter input so we don't
// rebuild every group's HTML on every keystroke when the bundle ships
// hundreds of log-source channels.
function debounce(fn, ms) {
  let t = 0;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function setStatus(text, kind = "") {
  const el = $("#status");
  $("#statusText").textContent = text;
  el.className = "status" + (kind ? " " + kind : "");
}

// chunk 20: per-render score caches so multiple renderers in the same
// refreshAll() pass don't recompute effectiveLogSourceScores /
// effectiveComponentScores 6+ times. Cleared at the start of every
// pass and populated lazily on first access.
function lsScoresMemo() {
  if (!state.renderCache) return effectiveLogSourceScores(state.inventory, state.attack);
  if (!state.renderCache.lsScores) state.renderCache.lsScores = effectiveLogSourceScores(state.inventory, state.attack);
  return state.renderCache.lsScores;
}
function compScoresMemo() {
  if (!state.renderCache) return effectiveComponentScores(state.inventory, state.attack);
  if (!state.renderCache.compScores) state.renderCache.compScores = effectiveComponentScores(state.inventory, state.attack);
  return state.renderCache.compScores;
}
function coverageMemo() {
  if (!state.renderCache) return runCoverage();
  if (!state.renderCache.coverage) state.renderCache.coverage = runCoverage();
  return state.renderCache.coverage;
}

// Re-render every view that depends on inventory or attack state. Cheap to
// run; coverage / mermaid are recomputed lazily and bail early when there's
// no attack data loaded.
function refreshAll() {
  state.renderCache = { lsScores: null, compScores: null, coverage: null };
  renderInventory();
  if (state.mergedInventory) renderInventoryV2();
  renderComponents();
  renderCoverage();
  renderGraph();
  renderExport();
  renderThreats();
}

// chunk 20: RAF-debounced refresh so a burst of toggles coalesces
// into one re-render. Reserved for hot paths added in future UI work
// (bulk enable/disable, score-burst clicks).
let _refreshScheduled = false;
function scheduleRefresh() {
  if (_refreshScheduled) return;
  _refreshScheduled = true;
  requestAnimationFrame(() => {
    _refreshScheduled = false;
    refreshAll();
  });
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
  // Refactor-merge chunk 2: when the merged-inventory flag is on,
  // route the Log Inventory tab to the unified panel
  // (#tab-inventory-v2). Tab buttons retain their original data-tab so
  // the highlight still tracks the user's click.
  const panelId = (id === "inventory" && state.mergedInventory) ? "inventory-v2" : id;
  $$(".panel").forEach(p => p.classList.toggle("active", p.id === `tab-${panelId}`));
  const sel = $("#tabsMobile");
  if (sel && sel.value !== id) sel.value = id;
  if (panelId === "inventory-v2") renderInventoryV2();
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
    onAttackLoaded("file", { autoSwitch: true });
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
    onAttackLoaded(state.attack.meta.source, { autoSwitch: true });
  } catch (e) {
    console.error("MITRE CTI fetch failed", e);
    setStatus(`MITRE CTI fetch failed: ${e.message}. Falling back to bundled offline ATT&CK.`, "error");
    setBanner(
      `<strong>Network fetch from github.com/mitre/cti failed.</strong> ` +
      `Your browser couldn't reach the MITRE CTI feed (corporate proxy, TLS interception, or offline). ` +
      `Falling back to the bundled offline ATT&CK (38 component categories, 38 representative techniques, 20 groups). ` +
      `Use this for the workflow demo, or upload a local STIX file on the MITRE CTI tab.`,
      "warn"
    );
    try {
      state.attack = await loadOfflineBundle();
      onAttackLoaded("offline-bundle", { autoSwitch: true });
    } catch (e2) {
      setStatus(`Both online and offline ATT&CK failed: ${e2.message}`, "error");
      setBanner(`<strong>Couldn't load any ATT&CK data:</strong> ${escapeHtml(e2.message)}`, "error");
    }
  }
}

function onAttackLoaded(source, opts = {}) {
  const a = state.attack;
  setStatus(`Loaded ${a.dataSources.length} component categories, ${a.techniques.length} techniques, ${a.groups?.length || 0} groups (${source})`, "ok");
  renderSetupSummary();
  populatePlatformFilter();
  populateTacticFilter();
  populateGroupSelectors();
  renderCustomLsComponentPicker(); // chunk 13: needs attack data
  refreshAll();
  // Only jump to the Inventory tab when the user explicitly triggered the
  // load (Load/Refresh button, STIX upload, sample-assessment CTA). On
  // boot — cache hit or offline-bundle fallback — the user should land on
  // the MITRE CTI tab so they can see what was loaded and read the
  // workflow help. Mobile users in particular were getting dumped into
  // tab 2 on cold start with no context.
  if (opts.autoSwitch && $(".tab.active").dataset.tab === "setup") {
    activateTab("inventory");
  }
}

function renderSetupSummary() {
  const a = state.attack;
  if (!a) { $("#setupSummary").innerHTML = ""; return; }
  $("#setupSummary").innerHTML = `
    <div class="grid">
      <div class="stat"><span class="label">Domain</span><span class="value">${escapeHtml(a.meta.domain)}</span></div>
      <div class="stat"><span class="label">Version</span><span class="value">${escapeHtml(String(a.meta.version))}</span></div>
      <div class="stat"><span class="label">Component categories</span><span class="value">${a.dataSources.length}</span></div>
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
const renderInventoryDebounced = debounce(() => renderInventory(), 180);
// Refactor-merge chunk 3: filter input on the merged Log Inventory tab.
$("#mergedInvFilter")?.addEventListener("input", e => {
  state.filters.mergedInvFilter = e.target.value;
  renderInventoryV2();
});

$("#dsFilter").addEventListener("input", e => {
  state.filters.ds = e.target.value.toLowerCase();
  renderInventoryDebounced();
});
$("#platformFilter").addEventListener("change", e => { state.filters.platform = e.target.value; renderInventory(); });
$("#onlyScored")?.addEventListener("change", e => { state.filters.onlyScored = e.target.checked; renderInventory(); });
document.querySelectorAll('input[name="inventoryGrouping"]').forEach(r => {
  r.addEventListener("change", e => {
    state.filters.inventoryGrouping = e.target.value;
    renderInventory();
  });
});

// Manual log-source entry. Lets the user type a (name, channel) tuple
// the bundle doesn't know about — e.g. a vendor-specific event ID, a
// Sigma-style logsource string, or a custom SIEM index. When the tuple
// matches an existing STIX log source the score drives coverage
// directly; otherwise the entry is persisted in inv.log_sources[] and
// rendered in the "Custom log sources" panel.
$("#customLsAdd")?.addEventListener("click", () => {
  const name = ($("#customLsName")?.value || "").trim();
  const channel = ($("#customLsChannel")?.value || "").trim();
  const score = Number($("#customLsScore")?.value || 0);
  const comment = ($("#customLsComment")?.value || "").trim();
  if (!name && !channel) {
    setStatus("Provide a name or channel", "error");
    return;
  }
  // chunk 13: also save the picked component_refs so the custom tuple
  // drives coverage on the components the user mapped it to.
  const componentRefs = Array.from(state.customLsComponentRefs);
  setLogSourceScore(state.inventory, name, channel, score, { comment, componentRefs });
  saveInventory(state.inventory);
  // Reset form, leave the panel open so users can add several quickly.
  if ($("#customLsName")) $("#customLsName").value = "";
  if ($("#customLsChannel")) $("#customLsChannel").value = "";
  if ($("#customLsComment")) $("#customLsComment").value = "";
  state.customLsComponentRefs.clear();
  renderCustomLsComponentPicker();
  const mapped = componentRefs.length > 0 ? ` (mapped to ${componentRefs.length} component${componentRefs.length === 1 ? "" : "s"})` : "";
  setStatus(`Added log source ${name}/${channel} (score ${score})${mapped}`, "ok");
  refreshAll();
});

// chunk 13: filter input + picker render for the manual-entry form's
// component map.
$("#customLsCompFilter")?.addEventListener("input", e => {
  state.filters.customLsCompFilter = e.target.value.toLowerCase();
  renderCustomLsComponentPicker();
});

function renderCustomLsComponentPicker() {
  const root = $("#customLsCompPicker");
  const countEl = $("#customLsCompCount");
  if (!root) return;
  if (!state.attack) {
    root.innerHTML = `<div class="comp-meta" style="padding:6px">Load ATT&CK data first.</div>`;
    if (countEl) countEl.textContent = "0 selected";
    return;
  }
  const filter = state.filters.customLsCompFilter || "";
  const all = state.attack.dataComponents.slice().sort((a, b) => a.name.localeCompare(b.name));
  const visible = all.filter(c => !filter || c.name.toLowerCase().includes(filter));
  if (countEl) countEl.textContent = `${state.customLsComponentRefs.size} selected`;
  let html = "";
  for (const c of visible) {
    const checked = state.customLsComponentRefs.has(c.id) ? "checked" : "";
    html += `<label class="component-pick">
      <input type="checkbox" data-comp-pick="${escapeAttr(c.id)}" ${checked} />
      <span>${escapeHtml(c.name)}</span>
    </label>`;
  }
  if (visible.length === 0) html = `<div class="comp-meta" style="padding:6px">No components match "${escapeHtml(filter)}".</div>`;
  root.innerHTML = html;
  root.querySelectorAll("input[data-comp-pick]").forEach(box => {
    box.addEventListener("change", () => {
      const id = box.getAttribute("data-comp-pick");
      if (box.checked) state.customLsComponentRefs.add(id);
      else state.customLsComponentRefs.delete(id);
      if (countEl) countEl.textContent = `${state.customLsComponentRefs.size} selected`;
    });
  });
}
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
  state.expanded = new Set();
  state.inventoryAutoExpandDone = false;
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
    // Re-arm the inventory auto-expand pass so the imported scored
    // groups surface without an extra click.
    state.expanded = new Set();
    state.inventoryAutoExpandDone = false;

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
    if (counts.sources === 0 && counts.logSources === 0) {
      setStatus(`Imported ${file.name} but it had no log sources`, "error");
    } else {
      const parts = [];
      if (counts.logSources) parts.push(`${counts.logSources} log sources`);
      if (counts.sources) parts.push(`${counts.sources} legacy v1 entries`);
      if (counts.overrides) parts.push(`${counts.overrides} component overrides`);
      setStatus(`Imported ${file.name}: ${parts.join(", ")}`, "ok");
      setBanner(`Imported <strong>${escapeHtml(file.name)}</strong>: ${parts.join(", ")}. Switch to <a href="#" data-goto="components">Data Components</a> or <a href="#" data-goto="coverage">Detection Strategies</a> to see the impact.`, "ok");
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
  const logSources = (inv.log_sources || []).length;
  const scoredLogSources = (inv.log_sources || []).filter(e => Number(e.score) > 0).length;
  return { sources, overrides, logSources, scoredLogSources };
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

  const compScores = compScoresMemo();
  const lsScores = lsScoresMemo();

  // Inventory summary spans the whole attack model (filter-independent).
  const totalComps = state.attack.dataComponents.length;
  const scoredComps = Array.from(compScores.values()).filter(v => v.score > 0).length;
  const totalLogSources = state.attack.logSources?.length || 0;
  const scoredLogSources = Array.from(lsScores.values()).filter(v => v.score > 0).length;
  // chunk 9: count log sources the user explicitly parked
  // (enabled === false). They round-trip on export but contribute 0 to
  // coverage, so surface the count as its own pill.
  const disabledLogSources = (state.inventory.log_sources || []).filter(e => e.enabled === false).length;
  if (summary) {
    summary.className = "inv-summary" + (scoredLogSources > 0 ? " populated" : "");
    summary.innerHTML = `
      <div class="pill"><strong>${scoredLogSources} / ${totalLogSources}</strong>log sources scored</div>
      <div class="pill"><strong>${scoredComps} / ${totalComps}</strong>data components covered</div>
      <div class="pill"><strong>${disabledLogSources}</strong>log sources disabled</div>
      <div class="pill"><strong>${state.inventory.name || "Default"}</strong>inventory name</div>
    `;
  }

  if (state.filters.inventoryGrouping === "name") {
    return renderInventoryByName(root, lsScores);
  }
  return renderInventoryByComponent(root, lsScores);
}

// chunk N: merged Data-Component → Log-Source → Channel hierarchy. Each
// Refactor-merge chunk 3: render the unified inventory hierarchy.
// Three levels — Data Component → Log Source name → Channel — built
// directly from the bundle's componentLogSources mapping. Each leaf
// channel exposes an Active checkbox (bound to setLogSourceEnabled)
// and a 0-5 score select (setLogSourceScore). The text filter
// matches across component / name / channel and force-expands hits.
//
// Score & enabled state are read via effectiveLogSourceScores so the
// rendering stays consistent with what coverage.js sees. A channel
// that maps to multiple data components renders once under each
// (state is shared because the backing inventory entry is keyed by
// lsKey(name, channel) — ticking once activates everywhere).
function renderInventoryV2() {
  const hier = $("#inventoryHierarchy");
  if (!hier) return;
  if (!state.attack) {
    hier.innerHTML = `<div style="padding:20px;color:var(--muted)">Load ATT&CK data first.</div>`;
    return;
  }
  const filter = (state.filters.mergedInvFilter || "").trim().toLowerCase();
  const lsScores = effectiveLogSourceScores(state.inventory, state.attack);
  const lsEntryByKey = new Map();
  for (const e of (state.inventory.log_sources || [])) {
    lsEntryByKey.set(`${(e.name || "").toLowerCase()}|${(e.channel || "").toLowerCase()}`, e);
  }

  // Build hierarchy: dc -> name -> channels[].
  const hierarchy = [];
  for (const dc of state.attack.dataComponents) {
    const lsByName = new Map();
    let activeChannels = 0;
    let totalChannels = 0;
    for (const lsId of (dc.logSourceIds || [])) {
      const ls = state.attack.logSourceById?.get(lsId);
      if (!ls) continue;
      const entry = lsEntryByKey.get(`${(ls.name || "").toLowerCase()}|${(ls.channel || "").toLowerCase()}`);
      const score = lsScores.get(ls.id)?.score || 0;
      const enabled = entry ? entry.enabled !== false : false;
      const active = enabled && score > 0;
      const channelMatch = filter
        ? `${dc.name} ${ls.name} ${ls.channel}`.toLowerCase().includes(filter)
        : true;
      if (filter && !channelMatch) continue;
      const name = ls.name || "(unnamed)";
      if (!lsByName.has(name)) lsByName.set(name, []);
      lsByName.get(name).push({ ls, entry, score, enabled, active });
      totalChannels += 1;
      if (active) activeChannels += 1;
    }
    if (lsByName.size === 0) continue;
    hierarchy.push({ dc, lsByName, activeChannels, totalChannels });
  }

  if (hierarchy.length === 0) {
    hier.innerHTML = filter
      ? `<div style="padding:20px;color:var(--muted)">No data components match "${escapeHtml(filter)}".</div>`
      : `<div style="padding:20px;color:var(--muted)">No data components in the loaded bundle.</div>`;
    return;
  }
  hierarchy.sort((a, b) => a.dc.name.localeCompare(b.dc.name));

  // Render
  let html = "";
  for (const h of hierarchy) {
    const compKey = `mvc:${h.dc.id}`;
    const compOpen = filter ? true : state.expanded.has(compKey);
    html += `
      <div class="ds-row" data-merged-comp="${escapeAttr(h.dc.id)}">
        <div class="toggle" data-merged-toggle="${escapeAttr(compKey)}">${compOpen ? "▾" : "▸"}</div>
        <div>
          <div class="ds-name">${escapeHtml(h.dc.name)}</div>
          <div class="ds-meta">${h.activeChannels} of ${h.totalChannels} channels active · ${h.lsByName.size} log source${h.lsByName.size === 1 ? "" : "s"}</div>
        </div>
        <div class="ds-meta">${h.totalChannels} channel${h.totalChannels === 1 ? "" : "s"}</div>
        <div class="ds-meta"></div>
      </div>`;
    if (!compOpen) continue;

    const sortedNames = Array.from(h.lsByName.keys()).sort((a, b) => a.localeCompare(b));
    for (const lsName of sortedNames) {
      const channels = h.lsByName.get(lsName);
      channels.sort((a, b) => (a.ls.channel || "").localeCompare(b.ls.channel || ""));
      const nameKey = `mvn:${h.dc.id}:${lsName}`;
      const nameOpen = filter ? true : state.expanded.has(nameKey);
      const nameActive = channels.filter(c => c.active).length;
      html += `
        <div class="ds-row" style="background:var(--surface-2,#fafafa);padding-left:24px" data-merged-name="${escapeAttr(nameKey)}">
          <div class="toggle" data-merged-toggle="${escapeAttr(nameKey)}">${nameOpen ? "▾" : "▸"}</div>
          <div>
            <div class="ds-name">${escapeHtml(lsName)}</div>
            <div class="ds-meta">${nameActive} of ${channels.length} channel${channels.length === 1 ? "" : "s"} active</div>
          </div>
          <div class="ds-meta"></div>
          <div class="ds-meta"></div>
        </div>`;
      if (!nameOpen) continue;
      for (const ch of channels) {
        const channelKey = `${ch.ls.name || ""}||${ch.ls.channel || ""}`;
        html += `
          <div class="dc-row by-name-row${ch.enabled ? "" : " parked"}" data-merged-channel="${escapeAttr(channelKey)}">
            <div>
              <div class="dc-name">${escapeHtml(ch.ls.name || "")} <span style="color:var(--muted);font-weight:400">/ ${escapeHtml(ch.ls.channel || "")}</span></div>
              <div class="dc-meta">${ch.active ? "active" : "inactive"}${ch.score > 0 ? ` · score ${ch.score}` : ""}</div>
            </div>
            <div class="dc-meta enable-cell">
              <label class="enable-toggle" title="Tick to count this channel toward analytics + coverage. Score must be > 0 for the chain to light up.">
                <input type="checkbox" data-merged-active="${escapeAttr(channelKey)}" ${ch.enabled ? "checked" : ""} />
                <span>${ch.enabled ? "active" : "inactive"}</span>
              </label>
            </div>
            <div>${scoreSelect(ch.score, "merged-ls", channelKey)}</div>
            <div></div>
          </div>`;
      }
    }
  }
  hier.innerHTML = html;

  // Wire interactions.
  hier.querySelectorAll("[data-merged-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const key = el.getAttribute("data-merged-toggle");
      if (state.expanded.has(key)) state.expanded.delete(key);
      else state.expanded.add(key);
      renderInventoryV2();
    });
  });
  hier.querySelectorAll("input[data-merged-active]").forEach(box => {
    box.addEventListener("change", () => {
      const [name, channel] = box.getAttribute("data-merged-active").split("||");
      setLogSourceEnabled(state.inventory, name, channel, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  hier.querySelectorAll("select[data-kind='merged-ls']").forEach(sel => {
    sel.addEventListener("change", () => {
      const [name, channel] = sel.getAttribute("data-key").split("||");
      setLogSourceScore(state.inventory, name, channel, Number(sel.value));
      saveInventory(state.inventory);
      refreshAll();
    });
  });
}

// data component (Process Creation, File Modification, Logon Session
// Creation, ...) groups the log-source names that feed it; each name
// expands to the (name, channel) tuples the bundle declares for that
// component. Each leaf has a single tick (active/inactive) and the
// 0-5 quality score. Default unticked everywhere — the user opts in by
// ticking the channels they actually collect.
//
// A single tuple (e.g. sysmon/1) can feed multiple data components and
// will appear once under each. The backing inventory entry is the same
// (keyed by lsKey), so ticking once activates it everywhere on the
// next refresh; each row exposes a "feeds N other components" hint.
function renderInventoryByComponent(root, lsScores) {
  const onlyScored = !!state.filters.onlyScored;
  const filterText = (state.filters.ds || "").trim();
  const filterPlatform = state.filters.platform || "";

  // O(1) lookup for inventory entries.
  const invByKey = new Map();
  for (const e of state.inventory.log_sources || []) {
    invByKey.set(((e.name || "") + "|" + (e.channel || "")).toLowerCase(), e);
  }

  // Custom (name, channel) entries that don't appear in any bundle
  // component get their own block at the top so users can still
  // edit / remove them. They don't fit the DC -> LS -> Channel tree
  // because they have no parent component.
  const knownKeys = new Set();
  for (const ls of state.attack.logSources || []) {
    knownKeys.add(((ls.name || "") + "|" + (ls.channel || "")).toLowerCase());
  }
  const customEntries = (state.inventory.log_sources || []).filter(e => {
    const k = ((e.name || "") + "|" + (e.channel || "")).toLowerCase();
    return !knownKeys.has(k);
  });

  // Build the hierarchy: componentId -> { dc, sourceName, lsByName,
  // totalChannels, scoredChannels }.
  const hierarchy = new Map();
  for (const dc of state.attack.dataComponents || []) {
    const lsByName = new Map();
    let totalChannels = 0, scoredChannels = 0;
    for (const lsId of dc.logSourceIds || []) {
      const ls = state.attack.logSourceById?.get(lsId);
      if (!ls) continue;
      const key = ((ls.name || "") + "|" + (ls.channel || "")).toLowerCase();
      const entry = invByKey.get(key);
      const score = entry && entry.score !== undefined ? clampInt(entry.score) : 0;
      const enabled = !!entry && entry.enabled !== false;
      if (filterText) {
        const hay = `${ls.name || ""} ${ls.channel || ""} ${dc.name || ""} ${entry?.comment || ""}`.toLowerCase();
        if (!hay.includes(filterText)) continue;
      }
      if (filterPlatform && !(ls.platforms || []).includes(filterPlatform)) continue;
      const nameKey = ls.name || "(unnamed)";
      if (!lsByName.has(nameKey)) lsByName.set(nameKey, { rows: [], scored: 0, total: 0 });
      const grp = lsByName.get(nameKey);
      grp.rows.push({ ls, entry, score, enabled });
      grp.total += 1;
      totalChannels += 1;
      if (enabled && score > 0) { grp.scored += 1; scoredChannels += 1; }
    }
    if (lsByName.size === 0) continue;
    if (onlyScored && scoredChannels === 0) continue;
    hierarchy.set(dc.id, {
      dc,
      lsByName,
      totalChannels,
      scoredChannels,
    });
  }

  // One-shot auto-expand of components with at least one active channel
  // (mirrors the by-name view; same flag so switching modes is sane).
  if (!state.inventoryAutoExpandDone) {
    let any = false;
    for (const [dcId, h] of hierarchy) {
      if (h.scoredChannels > 0) { state.expanded.add(`comp:${dcId}`); any = true; }
    }
    if (any || (state.inventory.log_sources || []).length > 0) {
      state.inventoryAutoExpandDone = true;
    }
  }

  let html = "";

  if (customEntries.length > 0) {
    html += `<div class="ds-row" style="background:var(--surface-2,#fafafa);font-weight:600">
      <div></div>
      <div>Custom log sources <span style="color:var(--muted);font-weight:400">(not in this ATT&CK bundle — kept for your records)</span></div>
      <div></div>
      <div></div>
    </div>`;
    for (const e of customEntries) {
      const score = Number(e.score) || 0;
      const enabled = e.enabled !== false;
      const channelKey = `${e.name || ""}||${e.channel || ""}`;
      html += `<div class="dc-row by-name-row${enabled ? "" : " parked"} custom-ls-row" data-custom-key="${escapeAttr(channelKey)}">
        <div>
          <div class="dc-name">${escapeHtml(e.name || "")} <span style="color:var(--muted);font-weight:400">/ ${escapeHtml(e.channel || "")}</span> <span style="color:var(--muted);font-weight:400">(custom)</span></div>
          <div class="dc-meta">${escapeHtml(e.comment || "no comment")}</div>
        </div>
        <div class="dc-meta enable-cell">
          <label class="enable-toggle">
            <input type="checkbox" data-ls-enable="${escapeAttr(channelKey)}" ${enabled ? "checked" : ""} />
            <span>${enabled ? "active" : "inactive"}</span>
          </label>
        </div>
        <div>${scoreSelect(score, "ls", channelKey)}</div>
        <div><button class="danger" data-remove-custom="${escapeAttr(channelKey)}" title="Remove">×</button></div>
      </div>`;
    }
  }

  if (hierarchy.size === 0 && customEntries.length === 0) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">No data components match your filter.</div>`;
    return;
  }

  // Sort components by name; render component group → log-source name
  // sub-groups → channel rows.
  const sortedDcIds = Array.from(hierarchy.keys()).sort((a, b) =>
    hierarchy.get(a).dc.name.localeCompare(hierarchy.get(b).dc.name));

  for (const dcId of sortedDcIds) {
    const h = hierarchy.get(dcId);
    const expandKey = `comp:${dcId}`;
    const expanded = (filterText || filterPlatform) ? true : state.expanded.has(expandKey);
    html += `
      <div class="ds-row" data-ds-id="${escapeAttr(expandKey)}">
        <div class="toggle" data-toggle="${escapeAttr(expandKey)}">${expanded ? "▾" : "▸"}</div>
        <div>
          <div class="ds-name">${escapeHtml(h.dc.name)}</div>
          <div class="ds-meta">${h.scoredChannels} of ${h.totalChannels} channels active · ${h.lsByName.size} log source${h.lsByName.size === 1 ? "" : "s"}</div>
        </div>
        <div class="ds-meta">${h.totalChannels} channel${h.totalChannels === 1 ? "" : "s"}</div>
        <div class="ds-meta"></div>
      </div>`;
    if (!expanded) continue;
    html += `<div class="ds-components open" data-components-for="${escapeAttr(expandKey)}">`;

    const sortedNames = Array.from(h.lsByName.keys()).sort((a, b) => a.localeCompare(b));
    for (const name of sortedNames) {
      const grp = h.lsByName.get(name);
      grp.rows.sort((a, b) => (a.ls.channel || "").localeCompare(b.ls.channel || ""));
      html += `<div class="ls-subgroup">
        <div class="ls-subgroup-h">
          <strong>${escapeHtml(name)}</strong>
          <span style="color:var(--muted);font-size:11px">${grp.scored} of ${grp.total} channel${grp.total === 1 ? "" : "s"} active</span>
        </div>`;
      for (const r of grp.rows) {
        const otherCompCount = (r.ls.componentIds?.size || r.ls.componentIds?.length || 1) - 1;
        const channelKey = `${r.ls.name || ""}||${r.ls.channel || ""}`;
        const meta = r.entry?.comment
          ? r.entry.comment
          : (otherCompCount > 0 ? `also feeds ${otherCompCount} other component${otherCompCount === 1 ? "" : "s"}` : "single-component channel");
        html += `<div class="dc-row by-name-row${r.enabled ? "" : " parked"}" data-ls-row="${escapeAttr(r.ls.id)}">
          <div>
            <div class="dc-name">${escapeHtml(r.ls.channel || "(no channel)")}</div>
            <div class="dc-meta">${escapeHtml(meta)}</div>
          </div>
          <div class="dc-meta enable-cell">
            <label class="enable-toggle">
              <input type="checkbox" data-ls-enable="${escapeAttr(channelKey)}" ${r.enabled ? "checked" : ""} />
              <span>${r.enabled ? "active" : "inactive"}</span>
            </label>
          </div>
          <div>${scoreSelect(r.score, "ls", channelKey)}</div>
        </div>`;
      }
      html += `</div>`;
    }

    html += `</div>`;
  }
  root.innerHTML = html;

  // Wire interactions — same handlers as renderInventoryByName.
  root.querySelectorAll("[data-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-toggle");
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      renderInventory();
    });
  });
  root.querySelectorAll("select[data-kind='ls']").forEach(sel => {
    sel.addEventListener("change", () => {
      const [name, channel] = sel.dataset.key.split("||");
      setLogSourceScore(state.inventory, name, channel, Number(sel.value));
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("input[type=checkbox][data-ls-enable]").forEach(box => {
    box.addEventListener("change", () => {
      const [name, channel] = box.dataset.lsEnable.split("||");
      setLogSourceEnabled(state.inventory, name, channel, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("[data-remove-custom]").forEach(btn => {
    btn.addEventListener("click", () => {
      const [name, channel] = btn.getAttribute("data-remove-custom").split("||");
      removeLogSource(state.inventory, name, channel);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
}

// chunk 9: by-name inventory view. Groups every (name, channel) tuple
// under its `name` (sysmon, windows-security, powershell, ...) so the
// user can see all event-codes from a single tool side by side. Each
// row has a score select, an enable/disable checkbox (disabled rows
// keep their saved score for export but contribute 0 to coverage),
// and — for custom user-added entries — a × remove. Each group also
// gets an inline "+ Add channel under <name>" form so users can score
// new event codes without leaving the tab.
function renderInventoryByName(root, lsScores) {
  const onlyScored = !!state.filters.onlyScored;
  const filterText = (state.filters.ds || "").trim();
  const filterPlatform = state.filters.platform || "";

  // O(1) lookups for inventory entries — replaces the per-bundle-row
  // .find() that turned the page into O(N×M) on big bundles.
  const invByKey = new Map();
  for (const e of state.inventory.log_sources || []) {
    const k = ((e.name || "") + "|" + (e.channel || "")).toLowerCase();
    invByKey.set(k, e);
  }

  // Map<name, { rows: Array<{ id, channel, score, enabled, comment, isCustom, ls? }>, total, scored }>
  const groups = new Map();
  const ensure = (name) => {
    if (!groups.has(name)) groups.set(name, { rows: [], total: 0, scored: 0 });
    return groups.get(name);
  };

  // Add every bundle log source.
  for (const ls of state.attack.logSources || []) {
    const entry = invByKey.get(((ls.name || "") + "|" + (ls.channel || "")).toLowerCase());
    const eff = lsScores.get(ls.id);
    const score = eff?.savedScore ?? 0;
    // Default unselected: a bundle log source with no inventory entry is
    // "I haven't onboarded this" — the row renders unticked / parked
    // until the user explicitly opts in (ticks the checkbox or sets a
    // score, both of which create an entry with enabled=true).
    const enabled = !!entry && entry.enabled !== false;
    const g = ensure(ls.name || "(unnamed)");
    g.rows.push({
      id: ls.id, name: ls.name, channel: ls.channel,
      score, enabled,
      comment: entry?.comment || "",
      isCustom: false,
      componentCount: ls.componentIds?.length || 0,
      platforms: ls.platforms || [],
    });
    g.total += 1;
    if (score > 0 && enabled) g.scored += 1;
  }

  // Add custom entries (those not in the bundle). Show them in their
  // matching name group so users see them alongside the bundled rows.
  const knownKeys = new Set(state.attack.logSources?.map(ls =>
    ((ls.name || "") + "|" + (ls.channel || "")).toLowerCase()
  ));
  for (const e of state.inventory.log_sources || []) {
    const key = ((e.name || "") + "|" + (e.channel || "")).toLowerCase();
    if (knownKeys.has(key)) continue;
    const g = ensure(e.name || "(unnamed)");
    g.rows.push({
      id: `custom:${key}`,
      name: e.name, channel: e.channel,
      score: clampInt(e.score) || 0,
      enabled: e.enabled !== false,
      comment: e.comment || "",
      isCustom: true,
      componentCount: 0,
      platforms: [],
    });
    g.total += 1;
    if ((Number(e.score) || 0) > 0 && e.enabled !== false) g.scored += 1;
  }

  if (groups.size === 0) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">No log sources in this bundle. Use the "+ Add log source by hand" form above to add custom entries.</div>`;
    return;
  }

  // Auto-expand groups that contain at least one scored row on the first
  // render after fresh inventory data lands. Lets users see their
  // scoring without an extra click after import — and keeps DOM-counting
  // assertions (e.g. countScoredLogSourceRows) working when the rest of
  // the page is rendered lazily.
  if (!state.inventoryAutoExpandDone) {
    let any = false;
    for (const [name, g] of groups) {
      if (g.scored > 0) { state.expanded.add(`name:${name}`); any = true; }
    }
    if (any || (state.inventory.log_sources || []).length > 0) {
      state.inventoryAutoExpandDone = true;
    }
  }

  // Per-row matcher for the search + platform filters. Custom rows have
  // no platform metadata, so the platform filter never excludes them
  // (otherwise users would lose visibility on their own entries).
  const rowMatches = (r) => {
    if (filterText) {
      const hay = `${r.name || ""} ${r.channel || ""} ${r.comment || ""}`.toLowerCase();
      if (!hay.includes(filterText)) return false;
    }
    if (filterPlatform && !r.isCustom) {
      if (!r.platforms.includes(filterPlatform)) return false;
    }
    return true;
  };

  // Sort group names alphabetically; sort rows within each group by channel.
  const sortedNames = Array.from(groups.keys()).sort((a, b) => a.localeCompare(b));
  let html = "";
  let visibleGroups = 0;
  for (const name of sortedNames) {
    const g = groups.get(name);
    if (onlyScored && g.scored === 0) continue;
    const visibleRows = g.rows.filter(rowMatches);
    if ((filterText || filterPlatform) && visibleRows.length === 0) continue;
    visibleRows.sort((a, b) => (a.channel || "").localeCompare(b.channel || ""));
    visibleGroups += 1;
    const expandKey = `name:${name}`;
    // When the user is actively filtering, force expansion so the matches
    // are visible without an extra click per group.
    const expanded = (filterText || filterPlatform) ? true : state.expanded.has(expandKey);
    const disabledCount = visibleRows.filter(r => !r.enabled).length;
    const customCount = visibleRows.filter(r => r.isCustom).length;
    const totalShown = visibleRows.length;
    const scoredShown = visibleRows.filter(r => r.score > 0 && r.enabled).length;
    html += `
      <div class="ds-row" data-ds-id="${escapeAttr(expandKey)}">
        <div class="toggle" data-toggle="${escapeAttr(expandKey)}">${expanded ? "▾" : "▸"}</div>
        <div>
          <div class="ds-name">${escapeHtml(name)}</div>
          <div class="ds-meta">${scoredShown} of ${totalShown} channels scored${disabledCount ? ` · ${disabledCount} disabled` : ""}</div>
        </div>
        <div class="ds-meta">${totalShown} channel${totalShown === 1 ? "" : "s"}</div>
        <div class="ds-meta">${customCount ? `${customCount} custom` : ""}</div>
      </div>`;
    // Lazy render: only emit the inner channel rows + add-channel form
    // when the group is expanded. Collapsed groups stay cheap — a few
    // hundred bundle log sources used to instantiate thousands of
    // hidden DOM nodes (selects, checkboxes, forms) every render.
    if (!expanded) continue;
    html += `
      <div class="ds-components open" data-components-for="${escapeAttr(expandKey)}">
        ${visibleRows.map(r => `
          <div class="dc-row by-name-row${r.enabled ? "" : " parked"}" data-ls-row="${escapeAttr(r.id)}">
            <div>
              <div class="dc-name">${escapeHtml(r.channel || "(no channel)")}${r.isCustom ? ' <span style="color:var(--muted);font-weight:400">(custom)</span>' : ""}</div>
              <div class="dc-meta">${escapeHtml(r.comment || (r.componentCount ? `feeds ${r.componentCount} component${r.componentCount === 1 ? "" : "s"}` : "no comment"))}</div>
            </div>
            <div class="dc-meta enable-cell">
              <label class="enable-toggle">
                <input type="checkbox" data-ls-enable="${escapeAttr(`${r.name || ""}||${r.channel || ""}`)}" ${r.enabled ? "checked" : ""} />
                <span>${r.enabled ? "enabled" : "parked"}</span>
              </label>
            </div>
            <div>${scoreSelect(r.score, "ls", `${r.name || ""}||${r.channel || ""}`)}</div>
            ${r.isCustom ? `<div><button class="danger" data-remove-custom="${escapeAttr(`${r.name || ""}||${r.channel || ""}`)}" title="Remove custom entry">×</button></div>` : ""}
          </div>
        `).join("")}
        <div class="dc-row add-channel-row">
          <form class="add-channel-form" data-add-channel-name="${escapeAttr(name)}">
            <span class="dc-meta">+ Add channel under <strong>${escapeHtml(name)}</strong>:</span>
            <input type="text" placeholder="channel / event ID" data-add-channel-channel />
            <select data-add-channel-score>
              <option value="0">0</option><option value="1">1</option><option value="2">2</option>
              <option value="3" selected>3</option><option value="4">4</option><option value="5">5</option>
            </select>
            <input type="text" placeholder="comment (optional)" data-add-channel-comment />
            <button type="submit">Add</button>
          </form>
        </div>
      </div>
    `;
  }
  if (visibleGroups === 0) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">No groups match your filter.</div>`;
    return;
  }
  root.innerHTML = html;

  // Wire interactions
  root.querySelectorAll("[data-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-toggle");
      if (state.expanded.has(id)) state.expanded.delete(id);
      else state.expanded.add(id);
      renderInventory();
    });
  });
  root.querySelectorAll("select[data-kind='ls']").forEach(sel => {
    sel.addEventListener("change", () => {
      const [name, channel] = sel.dataset.key.split("||");
      setLogSourceScore(state.inventory, name, channel, Number(sel.value));
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("input[type=checkbox][data-ls-enable]").forEach(box => {
    box.addEventListener("change", () => {
      const [name, channel] = box.dataset.lsEnable.split("||");
      setLogSourceEnabled(state.inventory, name, channel, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("[data-remove-custom]").forEach(btn => {
    btn.addEventListener("click", () => {
      const [name, channel] = btn.getAttribute("data-remove-custom").split("||");
      removeLogSource(state.inventory, name, channel);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("form.add-channel-form").forEach(form => {
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      const name = form.getAttribute("data-add-channel-name");
      const channel = form.querySelector("[data-add-channel-channel]")?.value.trim();
      const score = Number(form.querySelector("[data-add-channel-score]")?.value || 0);
      const comment = form.querySelector("[data-add-channel-comment]")?.value.trim();
      if (!channel) {
        setStatus("Provide a channel / event ID", "error");
        return;
      }
      setLogSourceScore(state.inventory, name, channel, score, { comment });
      saveInventory(state.inventory);
      // Keep the group expanded so the user sees the new row appear.
      state.expanded.add(`name:${name}`);
      setStatus(`Added ${name}/${channel} (score ${score})`, "ok");
      refreshAll();
    });
  });
}

function clampInt(n) {
  const v = Number(n);
  if (Number.isNaN(v)) return 0;
  return Math.max(0, Math.min(5, Math.round(v)));
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
  const compScores = compScoresMemo();
  const lsScores = lsScoresMemo();
  const filter = state.filters.component;
  const minScore = state.filters.componentScore;
  const all = state.attack.dataComponents.map(dc => {
    const eff = compScores.get(dc.id);
    const score = eff?.score ?? 0;
    return {
      id: dc.id,
      stixId: dc.id,
      name: dc.name,
      score,
      hasOverride: !!eff?.hasOverride,
      techCount: dc.techniqueIds.length,
      logSourceCount: (dc.logSourceIds || []).length,
      analyticCount: (dc.analyticIds || []).length,
      logSourceIds: dc.logSourceIds || [],
      analyticIds: dc.analyticIds || [],
    };
  });
  const total = all.length;
  const covered = all.filter(c => c.score > 0).length;
  const good = all.filter(c => c.score >= 3).length;
  const totalAnalytics = state.attack.analytics?.length || 0;
  const totalLogSources = state.attack.logSources?.length || 0;
  if (stats) {
    stats.innerHTML = `
      <div class="stat-card"><div class="label">Total components</div><div class="value">${total}</div></div>
      <div class="stat-card"><div class="label">Covered (score &gt; 0)</div><div class="value">${covered}</div><div class="sub">${pct(covered/Math.max(total,1))}</div></div>
      <div class="stat-card"><div class="label">Good (score &ge; 3)</div><div class="value">${good}</div></div>
      <div class="stat-card"><div class="label">Uncovered</div><div class="value" style="color:var(--bad)">${total - covered}</div></div>
      <div class="stat-card"><div class="label">Log sources (total)</div><div class="value">${totalLogSources}</div></div>
      <div class="stat-card"><div class="label">Analytics (total)</div><div class="value">${totalAnalytics}</div></div>
    `;
  }
  const rows = all.filter(c => {
    if (filter && !c.name.toLowerCase().includes(filter)) return false;
    if (minScore === "0" && c.score !== 0) return false;
    if (minScore === "1" && c.score < 1) return false;
    if (minScore === "3" && c.score < 3) return false;
    return true;
  }).sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  // chunk 12: colour-coded rows + expandable details so users can see
  // which log sources feed each component and which analytics
  // reference it. Coverage class drives a left-border + soft tint:
  //   covered (>=3) green, partial (1-2) amber, uncovered grey.
  let html = `<div class="tech-row header"><div></div><div>Component</div><div>Log sources / Analytics</div><div>Techniques</div><div>Score</div></div>`;
  for (const c of rows.slice(0, 1500)) {
    const coverageCls = c.score >= 3 ? "comp-covered" : (c.score >= 1 ? "comp-partial" : "comp-uncovered");
    const expanded = state.expanded.has(`comp:${c.id}`);
    html += `
      <div class="tech-row comp-row ${coverageCls}" data-comp-id="${escapeAttr(c.id)}">
        <div class="comp-toggle" data-comp-toggle="${escapeAttr(c.id)}" style="cursor:pointer;color:var(--muted)">${expanded ? "▾" : "▸"}</div>
        <div><strong>${escapeHtml(c.name)}</strong>${c.hasOverride ? ' <span class="cov-tag">scored</span>' : ' <span class="unc-tag">uncovered</span>'}</div>
        <div style="color:var(--muted);font-size:11px">${c.logSourceCount} log src · ${c.analyticCount} analytic${c.analyticCount === 1 ? "" : "s"}</div>
        <div style="color:var(--muted);font-size:11px">${c.techCount} tech</div>
        <div><span class="score-badge s${c.score}">${c.score}</span></div>
      </div>
      ${expanded ? renderComponentExpansion(c, lsScores) : ""}
    `;
  }
  root.innerHTML = html;

  // Toggle expansion on click of the chevron OR the row name.
  root.querySelectorAll("[data-comp-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-comp-toggle");
      const key = `comp:${id}`;
      if (state.expanded.has(key)) state.expanded.delete(key);
      else state.expanded.add(key);
      renderComponents();
    });
  });
}

// chunk 12: per-component expansion. Lists every log source feeding the
// component (with score + lit/unlit indicator) and the analytics that
// reference it. Bridges the gap "I see the component score but I don't
// know what's actually feeding it."
function renderComponentExpansion(c, lsScores) {
  const lsList = c.logSourceIds.map(id => {
    const ls = state.attack.logSourceById?.get(id);
    if (!ls) return null;
    const sc = lsScores.get(id)?.score || 0;
    return { id, name: ls.name, channel: ls.channel, score: sc };
  }).filter(Boolean);
  const ans = c.analyticIds.map(id => state.attack.analyticById?.get(id)).filter(Boolean);
  const lsHtml = lsList.length === 0
    ? `<div class="comp-meta">No log sources defined for this component.</div>`
    : lsList.map(ls => `<div class="comp-ls-row ${ls.score > 0 ? "ls-on" : "ls-off"}">
        <span class="dot"></span>
        <strong>${escapeHtml(ls.name)}</strong>
        <span style="color:var(--muted)">/ ${escapeHtml(ls.channel || "")}</span>
        <span class="score-badge s${ls.score}">${ls.score}</span>
      </div>`).join("");
  const anHtml = ans.length === 0
    ? `<div class="comp-meta">No analytics in this bundle reference this component.</div>`
    : ans.map(a => `<div class="comp-an-row">⚙ ${escapeHtml(a.name)}<span style="color:var(--muted);font-size:11px"> · ${a.logSourceIds?.length || 0} log source ref${(a.logSourceIds?.length || 0) === 1 ? "" : "s"}</span></div>`).join("");
  return `<div class="comp-expansion">
    <div class="comp-section">
      <div class="comp-section-h">Log sources feeding ${escapeHtml(c.name)}</div>
      ${lsHtml}
      <div class="comp-meta" style="margin-top:6px">Score on the <strong>Log Inventory</strong> tab to bring this component up.</div>
    </div>
    <div class="comp-section">
      <div class="comp-section-h">Analytics referencing this component</div>
      ${anHtml}
    </div>
  </div>`;
}

function scoreSelect(score, kind, key) {
  const opts = [0, 1, 2, 3, 4, 5].map(v => `<option value="${v}" ${v === score ? "selected" : ""}>${v} ${["None","Poor","Fair","Good","Very good","Excellent"][v]}</option>`).join("");
  return `<select data-kind="${escapeAttr(kind)}" data-key="${escapeAttr(key)}">${opts}</select>`;
}

function getSourceScore(ds) {
  const entry = (state.inventory.data_sources || []).find(e => e.data_source_name?.toLowerCase() === ds.name.toLowerCase());
  return entry ? Number(entry.score) || 0 : 0;
}

// Coverage engine walks Log Source -> Analytic -> Detection Strategy ->
// Technique. Bundles without detection strategies (older STIX dumps or
// custom uploads) produce zero-coverage rows but the call still returns a
// stable shape so the UI doesn't break.
function runCoverage() {
  if (!state.attack) return null;
  return computeCoverage(
    state.attack,
    effectiveLogSourceScores(state.inventory, state.attack),
    {
      analyticAggregation: state.filters.analyticAggregation || "min",
      riskAccepted: state.inventory.risk_accepted || null,
      disabledStrategies: state.inventory.disabled_strategies || null,
      manuallyCoveredStrategies: state.inventory.manually_covered_strategies || null,
    },
  );
}

// --- Detection Strategies summary (tab 4 header) ---
// Renders one card per x-mitre-detection-strategy in the loaded bundle,
// with lit/unlit status, the analytics it bundles, and the techniques it
// detects. Drives off the v2 coverage rows so the same min/avg toggle
// applies. When V2 isn't active (e.g. legacy bundle without
// detection-strategy STIX objects) the section stays empty.
function renderDetectionStrategies(coverage) {
  const root = $("#strategySummary");
  const countEl = $("#strategySummaryCount");
  if (!root) return;
  const strategies = state.attack?.detectionStrategies || [];
  if (countEl) countEl.textContent = String(strategies.length);
  if (!state.attack || strategies.length === 0) {
    root.innerHTML = `<div style="padding:12px;color:var(--muted)">No detection strategies in this bundle (legacy v1 data uses the technique table below).</div>`;
    return;
  }

  // Per-strategy lit/unlit + score derived from V2 coverage. If the
  // active engine isn't V2 (no logSourceScores), strategies fall back
  // to "unlit" with score 0.
  const techniqueByStratId = new Map(); // strategyId -> Set(techniqueAttackId)
  if (coverage && coverage.engine === "v2") {
    for (const row of coverage.rows) {
      for (const c of row.contributing || []) {
        if (!c.lit) continue;
        if (!techniqueByStratId.has(c.id)) techniqueByStratId.set(c.id, new Set());
        techniqueByStratId.get(c.id).add(row.attackId);
      }
    }
  }
  // Compute per-strategy display info using the same helpers V2 used.
  // We re-derive lit/score per analytic so the card matches whatever
  // V2 just computed — duplicate work but cheap (<150 strategies).
  const lsScores = state.attack.logSources ? lsScoresMemo() : new Map();
  const aggMode = state.filters.analyticAggregation || "min";
  const aggregate = aggMode === "avg"
    ? (vs) => vs.length ? vs.reduce((s, v) => s + v, 0) / vs.length : 0
    : (vs) => vs.length ? Math.min(...vs) : 0;

  let html = "";
  for (const st of strategies) {
    const stratEnabled = isStrategyEnabled(state.inventory, st.id);
    const stratManual = isStrategyManuallyCovered(state.inventory, st.id);
    const ans = (st.analyticIds || []).map(id => state.attack.analyticById?.get(id)).filter(Boolean);
    const litAns = [];
    let logSourceCount = 0;
    const analyticDetail = [];
    for (const a of ans) {
      const lsList = (a.logSourceIds || []).map(id => {
        const ls = state.attack.logSourceById?.get(id);
        return { id, name: ls?.name || "?", channel: ls?.channel || "", score: lsScores.get(id)?.score || 0 };
      });
      logSourceCount += lsList.length;
      const scores = lsList.map(l => l.score);
      const aLit = lsList.length > 0 && scores.every(s => s > 0);
      const aScore = aLit ? aggregate(scores) : 0;
      analyticDetail.push({ id: a.id, name: a.name, lit: aLit, score: aScore, lsList });
      if (aLit) litAns.push({ id: a.id, name: a.name, score: aScore });
    }
    const chainLit = stratEnabled && litAns.length > 0;
    const lit = chainLit || (stratEnabled && stratManual);
    let score = 0;
    if (chainLit && stratManual) score = Math.max(5, ...litAns.map(a => a.score));
    else if (chainLit) score = Math.max(...litAns.map(a => a.score));
    else if (stratManual) score = 5;
    const detectedTechIds = techniqueByStratId.get(st.id) || new Set();
    const detectedCount = detectedTechIds.size || (st.techniqueIds?.length || 0);
    const expanded = state.expanded.has(`strat:${st.id}`);
    const cardCls = lit ? " lit" : (stratEnabled ? "" : " parked");
    const manualCls = stratManual && stratEnabled ? " manual" : "";
    const statusBits = [];
    if (!stratEnabled) statusBits.push("<strong>parked</strong>");
    if (stratManual && stratEnabled) statusBits.push('<strong style="color:#3fb950">✓ manually covered</strong>');
    if (chainLit && !stratManual) statusBits.push("chain-lit");
    const statusSuffix = statusBits.length ? ` · ${statusBits.join(" · ")}` : "";
    html += `
      <div class="ds-row strategy-card${cardCls}${manualCls}" data-strat-id="${escapeAttr(st.id)}">
        <div class="strat-toggle" data-strat-toggle="${escapeAttr(st.id)}" style="cursor:pointer;color:var(--muted)">${expanded ? "▾" : "▸"}</div>
        <div>
          <div class="ds-name">${escapeHtml(st.name)} <span style="color:var(--muted);font-weight:400">${escapeHtml(st.attackId || "")}</span></div>
          <div class="ds-meta">${ans.length} analytic${ans.length === 1 ? "" : "s"} · ${logSourceCount} log-source ref${logSourceCount === 1 ? "" : "s"} · ${detectedCount} technique${detectedCount === 1 ? "" : "s"} detected${statusSuffix}</div>
        </div>
        <div class="ds-meta strat-toggles">
          ${litAns.length}/${ans.length} analytics lit
          <label class="enable-toggle" title="Park / unpark this strategy. Parked strategies don't count toward coverage even if you've claimed coverage.">
            <input type="checkbox" data-strat-enable="${escapeAttr(st.id)}" ${stratEnabled ? "checked" : ""} />
            <span>${stratEnabled ? "enabled" : "parked"}</span>
          </label>
          <label class="manual-cover-toggle" title="Claim manual coverage for this strategy. Use when you have a SIEM rule / EDR detection / etc. for it even if the bundle's analytic spec wouldn't auto-light from your log scores.">
            <input type="checkbox" data-strat-manual="${escapeAttr(st.id)}" ${stratManual ? "checked" : ""} />
            <span>covered</span>
          </label>
        </div>
        <div><span class="score-badge s${Math.round(score)}">${lit ? score.toFixed(1) : "○"}</span></div>
      </div>
      ${expanded ? renderStrategyExpansion(st, analyticDetail, detectedTechIds) : ""}`;
  }
  root.innerHTML = html;

  // Wire interactions
  root.querySelectorAll("[data-strat-toggle]").forEach(el => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-strat-toggle");
      const key = `strat:${id}`;
      if (state.expanded.has(key)) state.expanded.delete(key);
      else state.expanded.add(key);
      refreshAll();
    });
  });
  root.querySelectorAll("input[data-strat-enable]").forEach(box => {
    box.addEventListener("change", () => {
      const id = box.getAttribute("data-strat-enable");
      setStrategyEnabled(state.inventory, id, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("input[data-strat-manual]").forEach(box => {
    box.addEventListener("change", () => {
      const id = box.getAttribute("data-strat-manual");
      setStrategyManuallyCovered(state.inventory, id, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
  root.querySelectorAll("input[data-ls-enable-strat]").forEach(box => {
    box.addEventListener("change", () => {
      const [name, channel] = box.dataset.lsEnableStrat.split("||");
      setLogSourceEnabled(state.inventory, name, channel, box.checked);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
}

// chunk 14: strategy expansion. Lists each analytic, the log sources
// it requires (with score + lit dot), and an enable/disable toggle on
// every channel so users can park a feed straight from this tab.
function renderStrategyExpansion(strat, analyticDetail, detectedTechIds) {
  const techList = Array.from(detectedTechIds).sort();
  const anHtml = analyticDetail.length === 0
    ? `<div class="comp-meta">This strategy has no analytics yet.</div>`
    : analyticDetail.map(a => `<div class="strat-an-block ${a.lit ? "an-lit" : "an-unlit"}">
        <div class="strat-an-h">
          <span class="dot"></span>
          ⚙ <strong>${escapeHtml(a.name)}</strong>
          <span style="color:var(--muted);font-size:11px;margin-left:6px">${a.lit ? `lit · score ${a.score.toFixed(1)}` : "unlit · need every log source &gt; 0"}</span>
        </div>
        ${a.lsList.length === 0
          ? `<div class="comp-meta" style="padding-left:18px">No log sources required.</div>`
          : `<div class="strat-ls-list">
              ${a.lsList.map(ls => `<div class="strat-ls-row ${ls.score > 0 ? "ls-on" : "ls-off"}">
                <span class="dot"></span>
                <strong>${escapeHtml(ls.name)}</strong>
                <span style="color:var(--muted)">/ ${escapeHtml(ls.channel || "")}</span>
                <span class="score-badge s${ls.score}">${ls.score}</span>
                <label class="enable-toggle" style="margin-left:auto">
                  <input type="checkbox" data-ls-enable-strat="${escapeAttr(`${ls.name || ""}||${ls.channel || ""}`)}" ${(() => {
                    const e = state.inventory.log_sources?.find(x => (x.name||"").toLowerCase() === (ls.name||"").toLowerCase() && (x.channel||"").toLowerCase() === (ls.channel||"").toLowerCase());
                    // Default unselected: only checked when there's an explicit
                    // inventory entry that isn't parked. Matches the inventory
                    // tab — every channel starts as "I haven't onboarded this".
                    return e && e.enabled !== false ? "checked" : "";
                  })()} />
                  <span>park</span>
                </label>
              </div>`).join("")}
            </div>`}
      </div>`).join("");
  const techHtml = techList.length === 0
    ? `<div class="comp-meta">No techniques are currently lit by this strategy.</div>`
    : `<div class="strat-tech-list">${techList.slice(0, 12).map(t => `<span class="strat-tech-chip">${escapeHtml(t)}</span>`).join("")}${techList.length > 12 ? `<span class="strat-tech-chip more">+${techList.length - 12} more</span>` : ""}</div>`;
  return `<div class="comp-expansion strat-expansion">
    <div class="comp-section">
      <div class="comp-section-h">Required analytics &amp; log sources</div>
      ${anHtml}
    </div>
    <div class="comp-section">
      <div class="comp-section-h">Techniques this strategy lights up</div>
      ${techHtml}
    </div>
  </div>`;
}

// --- Coverage tab ---
$("#techFilter").addEventListener("input", e => { state.filters.tech = e.target.value.toLowerCase(); renderCoverage(); });
$("#tacticFilter").addEventListener("change", e => { state.filters.tactic = e.target.value; renderCoverage(); });
$("#coverageFilter").addEventListener("change", e => { state.filters.coverage = e.target.value; renderCoverage(); });
$("#analyticAggregation")?.addEventListener("change", e => { state.filters.analyticAggregation = e.target.value; refreshAll(); });

function renderCoverage() {
  const root = $("#techniqueTable");
  const stats = $("#coverageStats");
  if (!state.attack) {
    root.innerHTML = `<div style="padding:20px;color:var(--muted)">Load ATT&amp;CK data first.</div>`;
    stats.innerHTML = "";
    renderDetectionStrategies(null); // clears the summary
    return;
  }
  const cov = coverageMemo();
  renderDetectionStrategies(cov);

  const v2 = cov.engine === "v2";
  const detectableSub = v2 ? "have detection strategies" : "have data-component detections";
  // chunk 17: count manually-covered strategies as a separate signal
  // so users see how much of their coverage is "claimed" vs "chain-lit".
  const manualCount = Object.keys(state.inventory.manually_covered_strategies || {}).length;
  stats.innerHTML = `
    <div class="stat-card"><div class="label">Techniques (total)</div><div class="value">${cov.summary.total}</div></div>
    <div class="stat-card"><div class="label">Detectable</div><div class="value">${cov.summary.detectable}</div><div class="sub">${detectableSub}</div></div>
    <div class="stat-card"><div class="label">Covered</div><div class="value">${cov.summary.covered}</div><div class="sub">${pct(cov.summary.covered / Math.max(cov.summary.detectable,1))} of detectable</div></div>
    <div class="stat-card"><div class="label">Fully covered</div><div class="value">${cov.summary.fully}</div></div>
    <div class="stat-card"><div class="label">Partial</div><div class="value">${cov.summary.partial}</div></div>
    <div class="stat-card"><div class="label">Manually covered</div><div class="value">${manualCount}</div><div class="sub">strategies claimed</div></div>
    <div class="stat-card"><div class="label">Risk accepted</div><div class="value">${cov.summary.riskAccepted || 0}</div><div class="sub">acknowledged gaps</div></div>
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
    if (fCov === "uncovered" && (r.weightedScore > 0 || r.riskAccepted)) return false;
    if (fCov === "risk_accepted" && !r.riskAccepted) return false;
    return true;
  });

  let html = `<div class="tech-row header">
    <div>ID</div><div>Technique</div><div>Tactics</div><div>Coverage</div><div>Score / Risk</div>
  </div>`;
  for (const r of rows.slice(0, 1500)) {
    const fillPct = Math.round(r.ratio * 100);
    const riskCls = r.riskAccepted ? " risk-accepted" : "";
    html += `
      <div class="tech-row${riskCls}" title="${escapeAttr(`${r.coveredComponents}/${r.totalDetectingComponents} detecting components covered`)}">
        <div class="tech-id">${escapeHtml(r.attackId)}</div>
        <div>${escapeHtml(r.name)}${r.isSubtechnique ? ' <span style="color:var(--muted);font-size:11px">sub</span>' : ""}${r.riskAccepted ? ' <span class="risk-accepted-tag" title="Risk accepted">✓ risk accepted</span>' : ""}</div>
        <div class="tech-tactics">${escapeHtml(r.tactics.join(", "))}</div>
        <div>
          <div class="coverage-bar"><div class="fill" style="width:${fillPct}%"></div></div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">${r.coveredComponents}/${r.totalDetectingComponents} (${fillPct}%)</div>
        </div>
        <div>
          <span class="score-badge s${Math.round(r.weightedScore)}">${r.weightedScore.toFixed(2)}</span>
          <button class="risk-toggle" data-risk-tech="${escapeAttr(r.attackId)}" title="${r.riskAccepted ? "Un-accept risk" : "Accept risk for this technique"}">${r.riskAccepted ? "↺" : "✓"}</button>
        </div>
      </div>
    `;
  }
  if (rows.length > 1500) {
    html += `<div class="tech-row"><div></div><div style="color:var(--muted)">Showing first 1500 of ${rows.length} matches; refine filters.</div><div></div><div></div><div></div></div>`;
  }
  root.innerHTML = html;

  // Wire per-technique risk-accept toggle
  root.querySelectorAll("[data-risk-tech]").forEach(btn => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-risk-tech");
      const accepted = !isRiskAccepted(state.inventory, "techniques", id);
      setRiskAccepted(state.inventory, "techniques", id, accepted);
      saveInventory(state.inventory);
      refreshAll();
    });
  });
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
  const cov = coverageMemo();
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
  const cov = coverageMemo();
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
    <div class="stat-card"><div class="label">Risk accepted</div><div class="value">${gap.summary.riskAccepted || 0}</div><div class="sub">acknowledged gaps</div></div>
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

// chunk 8: log-source utility picker
$("#logSourcePickerFilter")?.addEventListener("input", e => {
  state.graph.logSourceFilter = e.target.value.toLowerCase();
  renderLogSourcePicker();
});
$("#logSourcePickerClear")?.addEventListener("click", () => {
  state.graph.selectedLogSources.clear();
  renderLogSourcePicker();
  renderLogSourceCascade();
});
$("#logSourcePickerSelectVisible")?.addEventListener("click", () => {
  for (const ls of visibleLogSourcesForPicker()) state.graph.selectedLogSources.add(ls.id);
  renderLogSourcePicker();
  renderLogSourceCascade();
});
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

  const compScores = compScoresMemo();

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
    sourceHost.innerHTML = `<div class="mermaid-empty">Pick a component category above.</div>`;
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

  // Log Source Utility cascade
  renderLogSourcePicker();
  renderLogSourceCascade();
}

// chunk 8: log-source picker. Returns the list of attack.logSources
// matching the current filter. Used both for rendering and for
// "Select all visible".
function visibleLogSourcesForPicker() {
  if (!state.attack) return [];
  const filter = state.graph.logSourceFilter || "";
  return state.attack.logSources.filter(ls => {
    if (!filter) return true;
    return (ls.name + "/" + (ls.channel || "")).toLowerCase().includes(filter);
  });
}

// Render a checkbox-per-log-source list. Selected log sources persist
// across re-renders via state.graph.selectedLogSources. The list is
// scrollable so the diagram below stays in view.
function renderLogSourcePicker() {
  const root = $("#logSourcePicker");
  if (!root) return;
  if (!state.attack) {
    root.innerHTML = `<div class="mermaid-empty" style="padding:8px">Load ATT&CK data first.</div>`;
    return;
  }
  const visible = visibleLogSourcesForPicker();
  const sel = state.graph.selectedLogSources;
  $("#logSourcePickerCount").textContent = `${sel.size} selected`;
  if (visible.length === 0) {
    root.innerHTML = `<div class="mermaid-empty" style="padding:8px">No log sources match "${escapeHtml(state.graph.logSourceFilter)}".</div>`;
    return;
  }
  const lsScores = lsScoresMemo();
  let html = "";
  for (const ls of visible) {
    const checked = sel.has(ls.id) ? "checked" : "";
    const score = lsScores.get(ls.id)?.score || 0;
    const scoreCls = score > 0 ? "score-on" : "score-off";
    html += `<label class="log-source-pick">
      <input type="checkbox" data-ls-id="${escapeAttr(ls.id)}" ${checked} />
      <strong>${escapeHtml(ls.name)}</strong>
      <span style="color:var(--muted)">/ ${escapeHtml(ls.channel || "")}</span>
      <span class="${scoreCls}">score ${score}</span>
    </label>`;
  }
  root.innerHTML = html;
  root.querySelectorAll("input[type=checkbox][data-ls-id]").forEach(box => {
    box.addEventListener("change", () => {
      const id = box.dataset.lsId;
      if (box.checked) state.graph.selectedLogSources.add(id);
      else state.graph.selectedLogSources.delete(id);
      $("#logSourcePickerCount").textContent = `${state.graph.selectedLogSources.size} selected`;
      renderLogSourceCascade();
    });
  });
}

// Render the cascade diagram. Smooth fade is driven by toggling a
// `.rendering` class on the host before/after mermaid renders so users
// see a brief opacity dip on each update instead of the diagram
// snapping in place.
function renderLogSourceCascade() {
  const host = $("#diagramLogSourceCascade");
  if (!host) return;
  if (!state.attack) {
    host.innerHTML = `<div class="mermaid-empty">Load ATT&CK data first.</div>`;
    return;
  }
  if (state.graph.selectedLogSources.size === 0) {
    host.innerHTML = `<div class="mermaid-empty">Pick log sources above to see what they unlock.</div>`;
    return;
  }
  const lsScores = lsScoresMemo();
  const source = logSourceCascadeDiagram({
    attack: state.attack,
    selectedLogSourceIds: state.graph.selectedLogSources,
    logSourceScores: lsScores,
    threats: state.threats,
    analyticAggregation: state.filters.analyticAggregation || "min",
  });
  host.classList.add("rendering");
  renderMermaidInto(host, source).finally(() => {
    requestAnimationFrame(() => host.classList.remove("rendering"));
  });
}

function populateGraphSelectors() {
  const sel = $("#graphSourceSelect");
  if (sel.options.length <= 1 && state.attack) {
    sel.innerHTML = `<option value="">Select a component category…</option>` +
      state.attack.dataSources.map(ds => `<option value="${escapeAttr(ds.id)}">${escapeHtml(ds.name)}</option>`).join("");
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
  const cov = coverageMemo();
  return buildNavigatorLayer({
    coverage: cov,
    attack: state.attack,
    name: $("#layerName").value || "Detection coverage",
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
          `Loaded the <strong>bundled offline ATT&CK</strong> (38 component categories, 38 representative techniques, 20 groups). ` +
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

// chunk 16: end-to-end "Run sample assessment" button.
// Loads the example log inventory + a sample threat group set in one
// click, then jumps to the Coverage tab so the user immediately sees
// what an end-to-end run looks like.
$("#runSampleAssessment")?.addEventListener("click", async () => {
  setStatus("Loading sample inventory + threats…", "busy");
  try {
    if (!state.attack) {
      try { state.attack = await loadOfflineBundle(); onAttackLoaded("offline-bundle"); }
      catch (_) { setStatus("Sample assessment needs ATT&CK data — load it on tab 1.", "error"); return; }
    }
    const [invText, threatsText] = await Promise.all([
      fetch("samples/inventory.example.yaml").then(r => r.text()),
      fetch("samples/threats.example.yaml").then(r => r.text()),
    ]);
    state.inventory = importYaml(invText);
    saveInventory(state.inventory);
    state.expanded = new Set();
    state.inventoryAutoExpandDone = false;
    state.threats = importThreatsYaml(threatsText);
    saveThreats(state.threats);
    refreshAll();
    activateTab("gaps");
    setStatus("Sample assessment loaded — see the Coverage tab.", "ok");
    setBanner(`<strong>Sample assessment loaded.</strong> The example inventory (sysmon, powershell, windows-security, zeek, …) is scored, the example threat groups are picked. The Coverage tab now shows what those groups can / can't be detected with this telemetry.`, "ok");
  } catch (e) {
    console.error("Sample assessment failed", e);
    setStatus(`Sample assessment failed: ${e.message}`, "error");
  }
});

// chunk 16: persistent help launcher. Opens the active tab's
// `<details class="tab-help">` block and scrolls it into view so the
// SOPs are always one click away.
$("#helpLauncher")?.addEventListener("click", () => {
  const activePanel = document.querySelector(".panel.active");
  const help = activePanel?.querySelector(".tab-help");
  if (!help) return;
  help.open = true;
  help.scrollIntoView({ behavior: "smooth", block: "start" });
});

// Pulse the help launcher briefly on first visit so users notice it.
try {
  if (!localStorage.getItem("help-launcher-seen")) {
    setTimeout(() => {
      $("#helpLauncher")?.classList.add("pulse");
      localStorage.setItem("help-launcher-seen", "1");
    }, 1200);
  }
} catch (_) { /* localStorage blocked, no-op */ }

// chunk 16: minimal guided tour. Five overlay steps walk the user
// through the workflow: Setup -> Inventory -> Detection Strategies ->
// Threats -> Coverage. Click Next to advance + auto-switch tabs.
const TUTORIAL_STEPS = [
  { tab: "setup",     title: "1. Load ATT&CK data",
    body: "Tab 1 fetches the latest MITRE ATT&CK STIX bundle (or falls back to the bundled offline copy). It's already loaded — you're ready to score." },
  { tab: "inventory", title: "2. Score your log inventory",
    body: "Tab 2 is where you tell the app what telemetry you collect. Each row is a (name, channel) tuple like sysmon/1 or windows-security/4624. Set 0–5; the score flows up to data components, analytics, detection strategies, and finally techniques. The example inventory was just loaded for the demo." },
  { tab: "coverage",  title: "3. See your detection strategies light up",
    body: "Tab 4 (Detection Strategies) shows every x-mitre-detection-strategy with a lit/unlit badge. Lit means at least one analytic is fully covered by your log scores. Click a chevron to drill into the analytics + log sources required." },
  { tab: "threats",   title: "4. Pick the threats you care about",
    body: "Tab 5 lists MITRE ATT&CK threat-actor groups (APT29, FIN7, …). Tick the ones that matter to your org — the Coverage tab will cross-reference what those groups do against what you can catch." },
  { tab: "gaps",      title: "5. Read the gap analysis",
    body: "Tab 6 cross-references your inventory against the picked threats. Gaps are techniques you can detect in principle but don't. Risk-accepted techniques (✓ on tab 4) are acknowledged gaps in their own bucket. Export the Navigator layer for a heatmap." },
];
let tutorialStep = 0;
$("#startTutorial")?.addEventListener("click", () => {
  tutorialStep = 0;
  showTutorialStep();
});
$("#tutorialNext")?.addEventListener("click", () => {
  tutorialStep += 1;
  if (tutorialStep >= TUTORIAL_STEPS.length) hideTutorial();
  else showTutorialStep();
});
$("#tutorialPrev")?.addEventListener("click", () => {
  if (tutorialStep > 0) tutorialStep -= 1;
  showTutorialStep();
});
$("#tutorialSkip")?.addEventListener("click", hideTutorial);
function showTutorialStep() {
  const step = TUTORIAL_STEPS[tutorialStep];
  if (!step) return hideTutorial();
  if (step.tab) activateTab(step.tab);
  $("#tutorialOverlay").hidden = false;
  $("#tutorialStepNum").textContent = String(tutorialStep + 1);
  $("#tutorialStepTotal").textContent = String(TUTORIAL_STEPS.length);
  $("#tutorialTitle").textContent = step.title;
  $("#tutorialBody").textContent = step.body;
  $("#tutorialPrev").disabled = tutorialStep === 0;
  $("#tutorialNext").textContent = tutorialStep === TUTORIAL_STEPS.length - 1 ? "Finish" : "Next →";
}
function hideTutorial() {
  $("#tutorialOverlay").hidden = true;
}
