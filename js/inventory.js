// Inventory state: per-log-source quality scores + legacy per-data-source
// scores, plus comments. Persists to localStorage. Imports / exports YAML
// and JSON.
//
// Schema (v2 — DeTT&CT-flavoured but extended for ATT&CK v18+ log sources):
// {
//   version: 1,
//   name: "string",
//   systems: [],                  // unused, retained for compatibility
//   log_sources: [                // v2 primary unit (ATT&CK v18+)
//     {
//        name: "sysmon",
//        channel: "1",
//        score: 4,                 // 0..5
//        comment: "",
//        applicable_to: ["all"],
//        date_connected: "2026-01-01",
//     }
//   ],
//   data_sources: [               // v1 legacy block — still imported / exported
//     { data_source_name, score, data_source: [{ name, score }], ... }
//   ]
// }
//
// Coverage chain:
//   log source score (v2 primary) ─┐
//   data source / component override (v1 legacy) ─┴─▶ effective component score
//                                                  ─▶ existing technique coverage logic

const STORAGE_KEY = "attack-inventory-v2";
const LEGACY_STORAGE_KEY = "attack-inventory-v1";

export const SCORE_KEYS = ["device_completeness", "data_field_completeness", "timeliness", "consistency", "retention"];

export function emptyInventory() {
  return {
    version: 1,
    name: "Default inventory",
    systems: [{ applicable_to: "all", description: "Default system" }],
    data_sources: [],
    log_sources: [],
  };
}

export function loadInventory() {
  // v2-first read; if missing, fall back to v1 (kept as a backup).
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") return migrate(parsed);
    }
  } catch (_) {}
  try {
    const legacy = localStorage.getItem(LEGACY_STORAGE_KEY);
    if (legacy) {
      const parsed = JSON.parse(legacy);
      if (parsed && typeof parsed === "object") return migrate(parsed);
    }
  } catch (_) {}
  return emptyInventory();
}

export function saveInventory(inv) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(inv));
}

export function resetInventory() {
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(LEGACY_STORAGE_KEY);
  return emptyInventory();
}

function migrate(inv) {
  if (!inv.data_sources) inv.data_sources = [];
  if (!inv.log_sources) inv.log_sources = [];
  if (!inv.version) inv.version = 1;
  if (!inv.name) inv.name = "Default inventory";
  return inv;
}

// Map keyed by canonical data source name (case-insensitive) -> entry
function indexInventory(inv) {
  const byName = new Map();
  for (const e of inv.data_sources || []) {
    if (!e?.data_source_name) continue;
    byName.set(e.data_source_name.toLowerCase(), e);
  }
  return byName;
}

// Map keyed by "<name>|<channel>" lowercased -> log_source entry
function indexLogSources(inv) {
  const byKey = new Map();
  for (const e of inv.log_sources || []) {
    if (!e?.name && !e?.channel) continue;
    const key = (e.name || "").toLowerCase() + "|" + (e.channel || "").toLowerCase();
    byKey.set(key, e);
  }
  return byKey;
}

function lsKey(name, channel) {
  return (name || "").toLowerCase() + "|" + (channel || "").toLowerCase();
}

// Get effective scores keyed by component STIX id.
// Returns Map(componentId -> { score:0..5, hasOverride, sourceName, componentName, comment })
//
// Score precedence (max wins so users adopting v2 don't accidentally lose
// coverage they'd already scored under v1):
//   1. v2 log_sources entry that maps to one of the component's log sources
//   2. v1 component override (data_sources[*].data_source[*])
//   3. v1 source score (data_sources[*].score)
export function effectiveComponentScores(inv, attack) {
  const idx = indexInventory(inv);
  const lsIdx = indexLogSources(inv);
  const out = new Map();
  for (const ds of attack.dataSources) {
    const entry = idx.get(ds.name.toLowerCase());
    const sourceScore = entry ? clampScore(entry.score) : 0;
    const compMap = new Map();
    if (entry) {
      for (const c of entry.data_source || []) {
        if (!c?.name) continue;
        compMap.set(c.name.toLowerCase(), c);
      }
    }
    for (const dc of ds.components) {
      const override = compMap.get(dc.name.toLowerCase());
      const hasV1Override = !!(override && override.score !== undefined && override.score !== null);
      const v1Score = hasV1Override ? clampScore(override.score) : (entry ? sourceScore : 0);

      // v2: project from any scored log source belonging to this component
      let v2Score = 0;
      let v2Any = false;
      for (const lsId of dc.logSourceIds || []) {
        const ls = attack.logSourceById?.get(lsId);
        if (!ls) continue;
        const lsEntry = lsIdx.get(lsKey(ls.name, ls.channel));
        if (lsEntry && lsEntry.score !== undefined && lsEntry.score !== null) {
          v2Any = true;
          v2Score = Math.max(v2Score, clampScore(lsEntry.score));
        }
      }

      const score = Math.max(v1Score, v2Score);
      if (!entry && !v2Any && !hasV1Override) continue;
      out.set(dc.id, {
        score,
        hasOverride: hasV1Override || v2Any,
        sourceName: ds.name,
        componentName: dc.name,
        comment: override?.comment ?? entry?.comment ?? "",
      });
    }
  }
  return out;
}

// Effective per-log-source scores. Keyed by log-source id.
// Returns Map(logSourceId -> { score:0..5, name, channel, comment, hasV2Override })
//
// If the user hasn't explicitly scored a log source, project the best
// score available from v1 inventory: max of any data-source-component
// override or parent data-source score across the components this log
// source belongs to. Lets v1 inventories light up the v2 UI naturally.
export function effectiveLogSourceScores(inv, attack) {
  const idx = indexInventory(inv);
  const lsIdx = indexLogSources(inv);
  const out = new Map();
  for (const ls of attack.logSources || []) {
    const explicit = lsIdx.get(lsKey(ls.name, ls.channel));
    let score = 0;
    let comment = "";
    let hasV2Override = false;
    if (explicit && explicit.score !== undefined && explicit.score !== null) {
      score = clampScore(explicit.score);
      comment = explicit.comment || "";
      hasV2Override = true;
    } else {
      // Project from v1: walk the components this log source belongs to.
      for (const compId of ls.componentIds || []) {
        const dc = attack.componentById?.get(compId);
        if (!dc) continue;
        const ds = attack.dataSourceById?.get(dc.sourceId);
        if (!ds) continue;
        const entry = idx.get(ds.name.toLowerCase());
        if (!entry) continue;
        const compName = dc.name.toLowerCase();
        const compOverride = (entry.data_source || []).find(c => (c?.name || "").toLowerCase() === compName);
        const candidate = (compOverride && compOverride.score !== undefined && compOverride.score !== null)
          ? clampScore(compOverride.score)
          : clampScore(entry.score);
        if (candidate > score) score = candidate;
      }
    }
    out.set(ls.id, {
      score,
      name: ls.name,
      channel: ls.channel,
      comment,
      hasV2Override,
    });
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

// v2: set the score for a single log source (name, channel) tuple.
export function setLogSourceScore(inv, name, channel, score, opts = {}) {
  if (!Array.isArray(inv.log_sources)) inv.log_sources = [];
  const key = lsKey(name, channel);
  let entry = inv.log_sources.find(e => lsKey(e.name, e.channel) === key);
  if (!entry) {
    entry = {
      name: name || "",
      channel: channel || "",
      applicable_to: ["all"],
      date_connected: today(),
      score: clampScore(score),
      comment: opts.comment || "",
    };
    inv.log_sources.push(entry);
  } else {
    entry.score = clampScore(score);
    if (opts.comment !== undefined) entry.comment = opts.comment;
    if (!entry.date_connected) entry.date_connected = today();
  }
  return inv;
}

export function setAllLogSources(inv, attack, score) {
  for (const ls of attack.logSources || []) setLogSourceScore(inv, ls.name, ls.channel, score);
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
  const doc = {
    version: 1.3,
    file_type: "data-source-administration",
    name: inv.name || "Default inventory",
    systems: inv.systems || [{ applicable_to: "all", description: "Default" }],
    log_sources: (inv.log_sources || []).map(e => ({
      name: e.name || "",
      channel: e.channel || "",
      applicable_to: e.applicable_to || ["all"],
      date_connected: e.date_connected || today(),
      score: clampScore(e.score),
      comment: e.comment || "",
    })),
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
  if (Array.isArray(doc.log_sources)) {
    inv.log_sources = doc.log_sources.map(e => ({
      name: e.name || "",
      channel: e.channel != null ? String(e.channel) : "",
      applicable_to: e.applicable_to || ["all"],
      date_connected: e.date_connected || today(),
      score: clampScore(e.score),
      comment: e.comment || "",
    })).filter(e => e.name || e.channel);
  }
  return inv;
}
