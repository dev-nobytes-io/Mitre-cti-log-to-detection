// Inventory state: per-data-source and per-component quality scores,
// plus comments. Persists to localStorage. Imports / exports YAML and JSON.
//
// Schema (DeTT&CT-flavoured but simplified):
// {
//   version: 1,
//   name: "string",
//   systems: [],                  // unused, retained for compatibility
//   data_sources: [
//     {
//        data_source_name: "Process",
//        applicable_to: ["all"],
//        date_registered: "2024-01-01",
//        date_connected: "2024-01-01",
//        available_for_data_analytics: true,
//        comment: "",
//        score: 3,                 // overall source score; component override below
//        data_quality: { device_completeness: 3, data_field_completeness: 3, timeliness: 3, consistency: 3, retention: 3 },
//        data_source: [
//          { name: "Process Creation", score: 4, comment: "" }
//        ]
//     }
//   ]
// }

const STORAGE_KEY = "attack-inventory-v1";

export const SCORE_KEYS = ["device_completeness", "data_field_completeness", "timeliness", "consistency", "retention"];

export function emptyInventory() {
  return {
    version: 1,
    name: "Default inventory",
    systems: [{ applicable_to: "all", description: "Default system" }],
    data_sources: [],
  };
}

export function loadInventory() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return emptyInventory();
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return migrate(parsed);
  } catch (_) {}
  return emptyInventory();
}

export function saveInventory(inv) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(inv));
}

export function resetInventory() {
  localStorage.removeItem(STORAGE_KEY);
  return emptyInventory();
}

function migrate(inv) {
  if (!inv.data_sources) inv.data_sources = [];
  if (!inv.version) inv.version = 1;
  if (!inv.name) inv.name = "Default inventory";
  return inv;
}

// Map keyed by canonical data source name (case-insensitive) -> entry
function indexInventory(inv) {
  const byName = new Map();
  for (const e of inv.data_sources) {
    if (!e?.data_source_name) continue;
    byName.set(e.data_source_name.toLowerCase(), e);
  }
  return byName;
}

// Get effective scores keyed by component STIX id.
// Returns Map(componentId -> { score:0..5, sourceName, componentName, comment })
export function effectiveComponentScores(inv, attack) {
  const idx = indexInventory(inv);
  const out = new Map();
  for (const ds of attack.dataSources) {
    const entry = idx.get(ds.name.toLowerCase());
    if (!entry) continue;
    const sourceScore = clampScore(entry.score);
    const compMap = new Map();
    for (const c of entry.data_source || []) {
      if (!c?.name) continue;
      compMap.set(c.name.toLowerCase(), c);
    }
    for (const dc of ds.components) {
      const override = compMap.get(dc.name.toLowerCase());
      const hasOverride = !!(override && override.score !== undefined && override.score !== null);
      const score = hasOverride ? clampScore(override.score) : sourceScore;
      out.set(dc.id, {
        score,
        hasOverride,
        sourceName: ds.name,
        componentName: dc.name,
        comment: override?.comment ?? entry.comment ?? "",
      });
    }
  }
  return out;
}

function clampScore(s) {
  const n = Number(s);
  if (Number.isNaN(n)) return 0;
  return Math.max(0, Math.min(5, Math.round(n)));
}

// Set the score for a data source (and optionally its components).
export function setSourceScore(inv, sourceName, score, opts = {}) {
  const idx = indexInventory(inv);
  let entry = idx.get(sourceName.toLowerCase());
  if (!entry) {
    entry = newEntry(sourceName);
    inv.data_sources.push(entry);
  }
  entry.score = clampScore(score);
  if (opts.cascade) {
    // Reset component overrides so they inherit
    entry.data_source = [];
  }
  if (opts.connectedDate && !entry.date_connected) entry.date_connected = today();
  if (!entry.date_registered) entry.date_registered = today();
  return inv;
}

export function setComponentScore(inv, sourceName, componentName, score) {
  const idx = indexInventory(inv);
  let entry = idx.get(sourceName.toLowerCase());
  if (!entry) {
    entry = newEntry(sourceName);
    inv.data_sources.push(entry);
  }
  if (!entry.data_source) entry.data_source = [];
  const lower = componentName.toLowerCase();
  let comp = entry.data_source.find(c => (c.name || "").toLowerCase() === lower);
  if (!comp) {
    comp = { name: componentName, score: clampScore(score), comment: "" };
    entry.data_source.push(comp);
  } else {
    comp.score = clampScore(score);
  }
  return inv;
}

export function setAllSources(inv, attack, score) {
  for (const ds of attack.dataSources) setSourceScore(inv, ds.name, score, { cascade: true });
  return inv;
}

function newEntry(name) {
  return {
    data_source_name: name,
    applicable_to: ["all"],
    date_registered: today(),
    date_connected: today(),
    available_for_data_analytics: true,
    score: 0,
    comment: "",
    data_quality: SCORE_KEYS.reduce((o, k) => (o[k] = 0, o), {}),
    data_source: [],
  };
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

// --- import / export ---

export function exportYaml(inv) {
  // Trim entries that have score 0 and no overrides? Keep all for transparency.
  const doc = {
    version: 1.2,
    file_type: "data-source-administration",
    name: inv.name || "Default inventory",
    systems: inv.systems || [{ applicable_to: "all", description: "Default" }],
    data_sources: (inv.data_sources || []).map(e => ({
      data_source_name: e.data_source_name,
      applicable_to: e.applicable_to || ["all"],
      date_registered: e.date_registered || today(),
      date_connected: e.date_connected || today(),
      available_for_data_analytics: e.available_for_data_analytics ?? true,
      comment: e.comment || "",
      score: clampScore(e.score),
      data_quality: e.data_quality || SCORE_KEYS.reduce((o, k) => (o[k] = clampScore(e.score), o), {}),
      data_source: (e.data_source || []).map(c => ({ name: c.name, score: clampScore(c.score), comment: c.comment || "" })),
    })),
  };
  // Use jsyaml from CDN (loaded globally)
  return window.jsyaml.dump(doc, { lineWidth: 120, noRefs: true });
}

export function importYaml(text) {
  const doc = window.jsyaml.load(text);
  return importDoc(doc);
}

export function exportJson(inv) {
  return JSON.stringify(inv, null, 2);
}

export function importJson(text) {
  const doc = JSON.parse(text);
  return importDoc(doc);
}

function importDoc(doc) {
  if (!doc || typeof doc !== "object") throw new Error("Invalid inventory document");
  const inv = emptyInventory();
  inv.name = doc.name || inv.name;
  if (Array.isArray(doc.systems)) inv.systems = doc.systems;
  if (Array.isArray(doc.data_sources)) {
    inv.data_sources = doc.data_sources.map(e => ({
      data_source_name: e.data_source_name || e.name,
      applicable_to: e.applicable_to || ["all"],
      date_registered: e.date_registered || today(),
      date_connected: e.date_connected || today(),
      available_for_data_analytics: e.available_for_data_analytics ?? true,
      comment: e.comment || "",
      score: clampScore(e.score),
      data_quality: e.data_quality || SCORE_KEYS.reduce((o, k) => (o[k] = clampScore(e.score), o), {}),
      data_source: Array.isArray(e.data_source) ? e.data_source.map(c => ({ name: c.name, score: clampScore(c.score), comment: c.comment || "" })) : [],
    })).filter(e => e.data_source_name);
  }
  return inv;
}
