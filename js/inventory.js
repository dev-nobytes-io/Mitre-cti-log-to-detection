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
//   mitigation_scores: {          // preventive-control maturity, keyed by
//     "M1032": { score: 4, comment: "" }   // ATT&CK mitigation attackId
//   }
//   custom_objects: [ { id, type: "mitigation", name, description } ]
//   custom_relations: [
//     { id, sourceRef, relation: "mitigates"|"maps-to-d3fend"|"maps-to-nist"|"maps-to-ism",
//       targetRef, targetLabel, comment }
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
    // chunk 10: per-kind risk-accepted dictionaries. Keys are stable
    // identifiers (lsKey for log sources, STIX component id, technique
    // attackId, group attackId). Value true means "we know we don't
    // have / can't get this and we accept the gap." Distinct from
    // score = 0 (haven't decided / haven't onboarded).
    risk_accepted: { log_sources: {}, components: {}, techniques: {}, groups: {} },
    // Preventive-control maturity, keyed by ATT&CK mitigation id (M1032
    // etc). Distinct from log_sources/detection scoring — this tracks
    // how well a *mitigation* (not a detection) is implemented, 0..5.
    mitigation_scores: {},
    // User-entered entities and relations for frameworks/controls the
    // loaded bundle and vendored D3FEND data don't cover (e.g. ISM, which
    // has no published ATT&CK crosswalk at all) — see js/custom-mappings.js.
    custom_objects: [],
    custom_relations: [],
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
  if (!inv.risk_accepted) inv.risk_accepted = { log_sources: {}, components: {}, techniques: {}, groups: {} };
  for (const k of ["log_sources", "components", "techniques", "groups"]) {
    if (!inv.risk_accepted[k]) inv.risk_accepted[k] = {};
  }
  if (!inv.disabled_strategies) inv.disabled_strategies = {};
  if (!inv.manually_covered_strategies) inv.manually_covered_strategies = {};
  if (!inv.mitigation_scores) inv.mitigation_scores = {};
  if (!Array.isArray(inv.custom_objects)) inv.custom_objects = [];
  if (!Array.isArray(inv.custom_relations)) inv.custom_relations = [];
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

      // v2: project from any scored *and enabled* log source belonging to
      // this component. Disabled entries (chunk 9: enabled === false) keep
      // their score in storage but contribute 0 to coverage so users can
      // park a feed without losing the saved score.
      let v2Score = 0;
      let v2Any = false;
      for (const lsId of dc.logSourceIds || []) {
        const ls = attack.logSourceById?.get(lsId);
        if (!ls) continue;
        const lsEntry = lsIdx.get(lsKey(ls.name, ls.channel));
        if (!lsEntry) continue;
        if (lsEntry.enabled === false) continue;
        if (lsEntry.score !== undefined && lsEntry.score !== null) {
          v2Any = true;
          v2Score = Math.max(v2Score, clampScore(lsEntry.score));
        }
      }
      // chunk 13: also project from custom user-added log sources that
      // explicitly map to this component via `component_refs`. Lets a
      // tuple the bundle doesn't know about (e.g. winlogbeat/9999)
      // still drive coverage on the components it feeds.
      for (const e of inv.log_sources || []) {
        if (!Array.isArray(e.component_refs) || !e.component_refs.includes(dc.id)) continue;
        if (e.enabled === false) continue;
        if (e.score === undefined || e.score === null) continue;
        v2Any = true;
        v2Score = Math.max(v2Score, clampScore(e.score));
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
    // chunk 9: explicit `enabled: false` means the user parked the feed
    // without losing the saved score. Treat as score = 0 for coverage
    // purposes; the saved score still round-trips on YAML export.
    const enabled = !explicit || explicit.enabled !== false;
    if (explicit && explicit.score !== undefined && explicit.score !== null) {
      score = enabled ? clampScore(explicit.score) : 0;
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
      enabled,
      savedScore: explicit && explicit.score !== undefined && explicit.score !== null ? clampScore(explicit.score) : score,
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
// Optional opts.componentRefs (array of STIX data-component ids) lets the
// caller record which data components a custom tuple feeds — chunk 13
// uses this so manual entries can drive coverage even when the (name,
// channel) doesn't match a known bundle log source.
//
// chunk 19: default-off — a brand-new entry with score > 0 is enabled
// (the user clearly intends to use it); a brand-new entry with score 0
// is disabled by default. Existing entries' `enabled` flag is
// untouched unless `opts.enable === true` is passed (e.g. from the
// picker view's "enable + score in one click" flow).
export function setLogSourceScore(inv, name, channel, score, opts = {}) {
  if (!Array.isArray(inv.log_sources)) inv.log_sources = [];
  const key = lsKey(name, channel);
  const clamped = clampScore(score);
  let entry = inv.log_sources.find(e => lsKey(e.name, e.channel) === key);
  if (!entry) {
    entry = {
      name: name || "",
      channel: channel || "",
      applicable_to: ["all"],
      date_connected: today(),
      score: clamped,
      enabled: opts.enable === true ? true : clamped > 0,
      comment: opts.comment || "",
      component_refs: Array.isArray(opts.componentRefs) ? [...opts.componentRefs] : [],
    };
    inv.log_sources.push(entry);
  } else {
    entry.score = clamped;
    if (opts.comment !== undefined) entry.comment = opts.comment;
    if (entry.enabled === undefined) entry.enabled = clamped > 0;
    if (opts.enable === true) entry.enabled = true;
    if (!entry.date_connected) entry.date_connected = today();
    if (Array.isArray(opts.componentRefs)) entry.component_refs = [...opts.componentRefs];
  }
  return inv;
}

// chunk 14: park an entire detection strategy. Stored as
// inv.disabled_strategies[stratId] = true. Disabled strategies are
// skipped entirely by computeCoverage — their analytics don't count
// toward technique coverage.
export function setStrategyEnabled(inv, strategyId, enabled) {
  if (!inv.disabled_strategies) inv.disabled_strategies = {};
  if (enabled) delete inv.disabled_strategies[strategyId];
  else inv.disabled_strategies[strategyId] = true;
  return inv;
}

export function isStrategyEnabled(inv, strategyId) {
  if (!inv.disabled_strategies) return true;
  return !inv.disabled_strategies[strategyId];
}

// chunk 17: manually claim coverage for a detection strategy.
// Distinct from disabled_strategies: this is a user override
// asserting "I have a SIEM rule / EDR detection / whatever for this
// strategy even if the bundle's analytic spec says I'd need more log
// sources." Marked-covered strategies count as lit at score = 5
// (full claimed coverage) regardless of the chain. Lets users get
// past the "0 coverage no matter what I do" state when their SIEM
// implements detections in ways the log-source chain can't model.
export function setStrategyManuallyCovered(inv, strategyId, covered) {
  if (!inv.manually_covered_strategies) inv.manually_covered_strategies = {};
  if (covered) inv.manually_covered_strategies[strategyId] = true;
  else delete inv.manually_covered_strategies[strategyId];
  return inv;
}

export function isStrategyManuallyCovered(inv, strategyId) {
  if (!inv.manually_covered_strategies) return false;
  return !!inv.manually_covered_strategies[strategyId];
}

// Preventive-control (ATT&CK mitigation) maturity scoring. Keyed by
// mitigation attackId (e.g. "M1032"), independent of the detective
// Log Source -> Analytic -> Strategy chain scored above. A score of 0
// (or no entry) means "not implemented / not assessed" — same
// unscored-by-default convention as log sources.
export function setMitigationScore(inv, mitigationId, score, comment) {
  if (!mitigationId) return inv;
  if (!inv.mitigation_scores) inv.mitigation_scores = {};
  const clamped = clampScore(score);
  const existing = inv.mitigation_scores[mitigationId];
  inv.mitigation_scores[mitigationId] = {
    score: clamped,
    comment: comment !== undefined ? comment : (existing?.comment || ""),
  };
  return inv;
}

// Returns Map<mitigationId, { score:0..5, comment }>. Mitigations with
// no saved entry are omitted — callers should treat a missing key as
// score 0 (matches how effectiveLogSourceScores callers already treat
// a missing map entry).
export function effectiveMitigationScores(inv) {
  const out = new Map();
  for (const [id, entry] of Object.entries(inv.mitigation_scores || {})) {
    out.set(id, { score: clampScore(entry?.score), comment: entry?.comment || "" });
  }
  return out;
}

// chunk 13: replace the component_refs[] for an existing log source
// without touching its score / comment / enabled flag. Used by the
// inventory tab's "Edit components" dialog on custom rows.
export function setLogSourceComponentRefs(inv, name, channel, componentIds) {
  if (!Array.isArray(inv.log_sources)) inv.log_sources = [];
  const key = lsKey(name, channel);
  const entry = inv.log_sources.find(e => lsKey(e.name, e.channel) === key);
  if (!entry) return inv;
  entry.component_refs = Array.isArray(componentIds) ? [...componentIds] : [];
  return inv;
}

// chunk 9: park a log source without dropping the saved score. Stores
// `enabled: false` on the entry; effectiveLogSourceScores treats it as
// score 0 for coverage purposes but the saved score round-trips on
// YAML/JSON export.
export function setLogSourceEnabled(inv, name, channel, enabled) {
  if (!Array.isArray(inv.log_sources)) inv.log_sources = [];
  const key = lsKey(name, channel);
  let entry = inv.log_sources.find(e => lsKey(e.name, e.channel) === key);
  if (!entry) {
    entry = {
      name: name || "",
      channel: channel || "",
      applicable_to: ["all"],
      date_connected: today(),
      score: 0,
      enabled: !!enabled,
      comment: "",
    };
    inv.log_sources.push(entry);
  } else {
    entry.enabled = !!enabled;
  }
  return inv;
}

export function setAllLogSources(inv, attack, score) {
  for (const ls of attack.logSources || []) setLogSourceScore(inv, ls.name, ls.channel, score);
  return inv;
}

// Drop the (name, channel) entry from inv.log_sources entirely. Used by
// the Log Inventory UI to delete custom entries that don't match any
// known STIX log source.
export function removeLogSource(inv, name, channel) {
  if (!Array.isArray(inv.log_sources)) return inv;
  const key = lsKey(name, channel);
  inv.log_sources = inv.log_sources.filter(e => lsKey(e.name, e.channel) !== key);
  return inv;
}

// chunk 10: risk-accepted helpers. `kind` ∈ {log_sources, components,
// techniques, groups}; `key` is the stable id for that kind (lsKey
// tuple, STIX component id, technique attackId, group attackId).
const RISK_KINDS = new Set(["log_sources", "components", "techniques", "groups"]);

export function setRiskAccepted(inv, kind, key, accepted) {
  if (!RISK_KINDS.has(kind)) return inv;
  if (!inv.risk_accepted) inv.risk_accepted = { log_sources: {}, components: {}, techniques: {}, groups: {} };
  if (!inv.risk_accepted[kind]) inv.risk_accepted[kind] = {};
  if (accepted) inv.risk_accepted[kind][key] = true;
  else delete inv.risk_accepted[kind][key];
  return inv;
}

export function isRiskAccepted(inv, kind, key) {
  if (!RISK_KINDS.has(kind)) return false;
  return !!(inv.risk_accepted && inv.risk_accepted[kind] && inv.risk_accepted[kind][key]);
}

// Resolve the risk-accepted key for a log source (name, channel) tuple.
export function logSourceRiskKey(name, channel) {
  return lsKey(name, channel);
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

// Export emits the v2 schema (log_sources only). Imports keep accepting
// the legacy data_sources block for back-compat with v1.2 DeTT&CT files,
// but new exports should not perpetuate the old layout.
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
      enabled: e.enabled !== false,
      comment: e.comment || "",
      component_refs: Array.isArray(e.component_refs) ? [...e.component_refs] : [],
    })),
    risk_accepted: inv.risk_accepted || { log_sources: {}, components: {}, techniques: {}, groups: {} },
    disabled_strategies: inv.disabled_strategies || {},
    manually_covered_strategies: inv.manually_covered_strategies || {},
    mitigation_scores: inv.mitigation_scores || {},
    custom_objects: inv.custom_objects || [],
    custom_relations: inv.custom_relations || [],
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
    inv.log_sources = doc.log_sources.map(e => {
      const score = clampScore(e.score);
      // chunk 19: default-off semantics. If `enabled` is explicitly
      // set, honour it. Otherwise infer: a row with score > 0 is
      // assumed enabled (preserves persona / DeTT&CT-import behaviour
      // — users who scored a row clearly meant to enable it). Rows
      // without an explicit score and no `enabled` flag default off.
      const enabled = (e.enabled !== undefined) ? (e.enabled !== false) : (score > 0);
      return {
        name: e.name || "",
        channel: e.channel != null ? String(e.channel) : "",
        applicable_to: e.applicable_to || ["all"],
        date_connected: e.date_connected || today(),
        score,
        enabled,
        comment: e.comment || "",
        component_refs: Array.isArray(e.component_refs) ? e.component_refs.filter(x => typeof x === "string") : [],
      };
    }).filter(e => e.name || e.channel);
  }
  if (doc.risk_accepted && typeof doc.risk_accepted === "object") {
    inv.risk_accepted = {
      log_sources: { ...(doc.risk_accepted.log_sources || {}) },
      components:  { ...(doc.risk_accepted.components || {}) },
      techniques:  { ...(doc.risk_accepted.techniques || {}) },
      groups:      { ...(doc.risk_accepted.groups || {}) },
    };
  }
  if (doc.disabled_strategies && typeof doc.disabled_strategies === "object") {
    inv.disabled_strategies = { ...doc.disabled_strategies };
  }
  if (doc.manually_covered_strategies && typeof doc.manually_covered_strategies === "object") {
    inv.manually_covered_strategies = { ...doc.manually_covered_strategies };
  }
  if (doc.mitigation_scores && typeof doc.mitigation_scores === "object") {
    inv.mitigation_scores = {};
    for (const [id, entry] of Object.entries(doc.mitigation_scores)) {
      inv.mitigation_scores[id] = { score: clampScore(entry?.score), comment: entry?.comment || "" };
    }
  }
  if (Array.isArray(doc.custom_objects)) {
    inv.custom_objects = doc.custom_objects
      .filter(o => o && o.id && o.type)
      .map(o => ({ id: o.id, type: o.type, name: o.name || o.id, description: o.description || "" }));
  }
  if (Array.isArray(doc.custom_relations)) {
    inv.custom_relations = doc.custom_relations
      .filter(r => r && r.id && r.sourceRef && r.relation)
      .map(r => ({
        id: r.id, sourceRef: r.sourceRef, relation: r.relation,
        targetRef: r.targetRef || "", targetLabel: r.targetLabel || "", comment: r.comment || "",
      }));
  }
  return inv;
}
