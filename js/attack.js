// Loads and indexes a MITRE ATT&CK STIX 2.x bundle from
// github.com/mitre-attack/attack-stix-data (the canonical v18+ feed; the
// legacy github.com/mitre/cti mirror is being phased out).
// Exposes:
//   loadAttack({domain, url, signal, onProgress}) -> AttackData
//   loadAttackFromBundle(bundle) -> AttackData
//   loadOfflineBundle() -> AttackData      // bundled with the site
//
// Caches the raw bundle in IndexedDB keyed by domain+version.

const CTI_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master";
const OFFLINE_BUNDLE_URL = "vendor/attack-offline.json";
const DB_NAME = "attack-cache";
const DB_STORE = "bundles";

function defaultUrl(domain) {
  return `${CTI_BASE}/${domain}/${domain}.json`;
}

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(DB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readonly");
    const req = tx.objectStore(DB_STORE).get(key);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function dbPut(key, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function clearAttackCache() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, "readwrite");
    tx.objectStore(DB_STORE).clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadAttack({ domain = "enterprise-attack", url, onProgress, force = false, cacheOnly = false } = {}) {
  const cacheKey = url || domain;
  if (!force) {
    try {
      const cached = await dbGet(cacheKey);
      if (cached && cached.bundle) {
        onProgress?.({ phase: "cache", message: `Loaded ${domain} from cache` });
        return indexBundle(cached.bundle, { domain, source: "cache", fetchedAt: cached.fetchedAt });
      }
    } catch (_) {
      // ignore cache errors
    }
  }
  if (cacheOnly) {
    const err = new Error("No cached ATT&CK data");
    err.code = "NO_CACHE";
    throw err;
  }
  const fetchUrl = url || defaultUrl(domain);
  onProgress?.({ phase: "fetch", message: `Fetching ${fetchUrl}` });
  const res = await fetch(fetchUrl, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to fetch ${fetchUrl}: ${res.status} ${res.statusText}`);
  const bundle = await res.json();
  const fetchedAt = new Date().toISOString();
  try { await dbPut(cacheKey, { bundle, fetchedAt }); } catch (_) { /* quota etc */ }
  onProgress?.({ phase: "parse", message: `Parsing ${bundle.objects?.length ?? 0} objects` });
  return indexBundle(bundle, { domain, source: "network", fetchedAt });
}

export function loadAttackFromBundle(bundle, meta = {}) {
  return indexBundle(bundle, { domain: meta.domain || "custom", source: meta.source || "file", fetchedAt: new Date().toISOString() });
}

// Loads the offline ATT&CK bundle that ships with the static site.
// Same-origin so it works even when github.com is blocked.
export async function loadOfflineBundle({ onProgress } = {}) {
  onProgress?.({ phase: "fetch", message: `Loading bundled offline ATT&CK` });
  const res = await fetch(OFFLINE_BUNDLE_URL, { cache: "force-cache" });
  if (!res.ok) throw new Error(`Failed to load bundled ATT&CK: ${res.status}`);
  const bundle = await res.json();
  return indexBundle(bundle, { domain: "enterprise-attack-offline", source: "offline-bundle", fetchedAt: new Date().toISOString() });
}

function externalAttackId(obj) {
  const ext = (obj.external_references || []).find(r => r.source_name === "mitre-attack" && r.external_id);
  return ext?.external_id;
}

// Synthetic log-source id derived from (name, channel) so it survives YAML
// round-trips through the inventory file (MITRE doesn't ship log sources as
// top-level STIX objects — they're embedded tuples inside data components).
function logSourceId(name, channel) {
  const slug = (s) => String(s ?? "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
  return `logsource--${slug(name)}--${slug(channel)}`;
}

function indexBundle(bundle, meta) {
  const objects = bundle.objects || [];
  const byId = new Map();
  for (const o of objects) byId.set(o.id, o);

  const dataSources = [];          // x-mitre-data-source
  const dataComponents = [];       // x-mitre-data-component
  const techniques = [];           // attack-pattern (active)
  const tactics = [];              // x-mitre-tactic
  const intrusionSets = [];        // intrusion-set (threat-actor groups)
  const analyticObjs = [];         // x-mitre-analytic (v18+)
  const detectionStrategyObjs = []; // x-mitre-detection-strategy (v18+)
  const detectsRels = [];          // relationship type=detects
  const usesRels = [];             // relationship type=uses (group/software -> technique)

  for (const o of objects) {
    if (o.x_mitre_deprecated || o.revoked) continue;
    switch (o.type) {
      case "x-mitre-data-source": dataSources.push(o); break;
      case "x-mitre-data-component": dataComponents.push(o); break;
      case "attack-pattern": techniques.push(o); break;
      case "x-mitre-tactic": tactics.push(o); break;
      case "intrusion-set": intrusionSets.push(o); break;
      case "x-mitre-analytic": analyticObjs.push(o); break;
      case "x-mitre-detection-strategy": detectionStrategyObjs.push(o); break;
      case "relationship":
        if (o.relationship_type === "detects") detectsRels.push(o);
        else if (o.relationship_type === "uses") usesRels.push(o);
        break;
    }
  }

  // Build data-component -> data-source map (component.x_mitre_data_source_ref points at source)
  const componentsBySource = new Map();
  const componentById = new Map();
  for (const dc of dataComponents) {
    componentById.set(dc.id, dc);
    const srcId = dc.x_mitre_data_source_ref;
    if (!componentsBySource.has(srcId)) componentsBySource.set(srcId, []);
    componentsBySource.get(srcId).push(dc);
  }

  // tactic shortname -> tactic object (for resolving kill_chain_phases)
  const tacticsByShortname = new Map();
  for (const t of tactics) tacticsByShortname.set(t.x_mitre_shortname, t);

  // Build technique -> data components (via detects relationships: source=data-component, target=technique)
  const techniqueComponents = new Map();   // techniqueId -> Set(componentId)
  const componentTechniques = new Map();   // componentId -> Set(techniqueId)
  for (const r of detectsRels) {
    const compId = r.source_ref;
    const techId = r.target_ref;
    const dc = componentById.get(compId);
    const tech = byId.get(techId);
    if (!dc || !tech || tech.type !== "attack-pattern") continue;
    if (!techniqueComponents.has(techId)) techniqueComponents.set(techId, new Set());
    techniqueComponents.get(techId).add(compId);
    if (!componentTechniques.has(compId)) componentTechniques.set(compId, new Set());
    componentTechniques.get(compId).add(techId);
  }

  // ---- v18+ chain: log sources -> data components -> analytics -> detection strategies -> techniques ----
  // Log sources live inside data components as x_mitre_log_sources: [{name, channel}].
  // We dedupe (name, channel) tuples across all components into a flat logSourceList,
  // and remember which component(s) each tuple came from.
  const logSourceById = new Map(); // logSourceId -> { id, name, channel, componentIds: Set, platforms: Set }
  const componentLogSourceIds = new Map(); // componentId -> Set(logSourceId)
  for (const dc of dataComponents) {
    const tuples = Array.isArray(dc.x_mitre_log_sources) ? dc.x_mitre_log_sources : [];
    if (!tuples.length) continue;
    if (!componentLogSourceIds.has(dc.id)) componentLogSourceIds.set(dc.id, new Set());
    for (const t of tuples) {
      if (!t || (!t.name && !t.channel)) continue;
      const id = logSourceId(t.name, t.channel);
      let entry = logSourceById.get(id);
      if (!entry) {
        entry = { id, name: t.name || "", channel: t.channel || "", componentIds: new Set(), platforms: new Set() };
        logSourceById.set(id, entry);
      }
      entry.componentIds.add(dc.id);
      // Inherit platforms from the parent data source
      const srcId = dc.x_mitre_data_source_ref;
      const src = byId.get(srcId);
      for (const p of src?.x_mitre_platforms || []) entry.platforms.add(p);
      componentLogSourceIds.get(dc.id).add(id);
    }
  }

  // Analytics: each references log sources via x_mitre_log_source_references[]
  // (each entry is { x_mitre_data_component_ref, name, channel }).
  const analyticById = new Map();
  const componentAnalyticIds = new Map(); // componentId -> Set(analyticId)
  for (const an of analyticObjs) {
    const refs = Array.isArray(an.x_mitre_log_source_references) ? an.x_mitre_log_source_references : [];
    const lsIds = new Set();
    const compIds = new Set();
    for (const r of refs) {
      if (!r) continue;
      if (r.name || r.channel) lsIds.add(logSourceId(r.name, r.channel));
      if (r.x_mitre_data_component_ref) compIds.add(r.x_mitre_data_component_ref);
    }
    analyticById.set(an.id, {
      id: an.id,
      stixId: an.id,
      name: an.name || "",
      description: an.description || "",
      platforms: an.x_mitre_platforms || [],
      logSourceIds: Array.from(lsIds),
      componentIds: Array.from(compIds),
    });
    for (const cid of compIds) {
      if (!componentAnalyticIds.has(cid)) componentAnalyticIds.set(cid, new Set());
      componentAnalyticIds.get(cid).add(an.id);
    }
  }

  // Detection strategies: x_mitre_analytic_refs[] -> analytics; detects rels -> techniques.
  const detectionStrategyById = new Map();
  const analyticStrategyIds = new Map(); // analyticId -> Set(strategyId)
  const strategyTechniqueIds = new Map(); // strategyId -> Set(techniqueId)
  const techniqueStrategyIds = new Map(); // techniqueId -> Set(strategyId)
  for (const s of detectionStrategyObjs) {
    const aRefs = Array.isArray(s.x_mitre_analytic_refs) ? s.x_mitre_analytic_refs.filter(id => analyticById.has(id)) : [];
    detectionStrategyById.set(s.id, {
      id: s.id,
      stixId: s.id,
      attackId: externalAttackId(s),
      name: s.name || "",
      description: s.description || "",
      analyticIds: aRefs,
      techniqueIds: [], // filled from detects rels below
    });
    for (const aid of aRefs) {
      if (!analyticStrategyIds.has(aid)) analyticStrategyIds.set(aid, new Set());
      analyticStrategyIds.get(aid).add(s.id);
    }
  }
  // detects rels with strategy as source ref (v18+ pattern)
  for (const r of detectsRels) {
    const src = detectionStrategyById.get(r.source_ref);
    if (!src) continue;
    const tech = byId.get(r.target_ref);
    if (!tech || tech.type !== "attack-pattern") continue;
    if (!strategyTechniqueIds.has(r.source_ref)) strategyTechniqueIds.set(r.source_ref, new Set());
    strategyTechniqueIds.get(r.source_ref).add(r.target_ref);
    if (!techniqueStrategyIds.has(r.target_ref)) techniqueStrategyIds.set(r.target_ref, new Set());
    techniqueStrategyIds.get(r.target_ref).add(r.source_ref);
  }
  for (const [sid, tset] of strategyTechniqueIds) {
    detectionStrategyById.get(sid).techniqueIds = Array.from(tset);
  }

  // Normalize objects we care about
  const dataSourceList = dataSources.map(ds => {
    const components = (componentsBySource.get(ds.id) || []).map(dc => ({
      id: dc.id,
      stixId: dc.id,
      name: dc.name,
      description: dc.description || "",
      sourceId: ds.id,
      techniqueIds: Array.from(componentTechniques.get(dc.id) || []),
      logSourceIds: Array.from(componentLogSourceIds.get(dc.id) || []),
      analyticIds: Array.from(componentAnalyticIds.get(dc.id) || []),
    }));
    return {
      id: ds.id,
      stixId: ds.id,
      attackId: externalAttackId(ds),
      name: ds.name,
      description: ds.description || "",
      platforms: ds.x_mitre_platforms || [],
      collectionLayers: ds.x_mitre_collection_layers || [],
      contributors: ds.x_mitre_contributors || [],
      components,
    };
  }).sort((a, b) => a.name.localeCompare(b.name));

  const techniqueList = techniques
    .filter(t => !(t.x_mitre_is_subtechnique && false)) // keep all by default
    .map(t => {
      const tacticShortnames = (t.kill_chain_phases || [])
        .filter(k => k.kill_chain_name === "mitre-attack" || k.kill_chain_name === "mitre-mobile-attack" || k.kill_chain_name === "mitre-ics-attack")
        .map(k => k.phase_name);
      return {
        id: t.id,
        stixId: t.id,
        attackId: externalAttackId(t),
        name: t.name,
        description: t.description || "",
        platforms: t.x_mitre_platforms || [],
        isSubtechnique: !!t.x_mitre_is_subtechnique,
        tactics: tacticShortnames,
        componentIds: Array.from(techniqueComponents.get(t.id) || []),
        strategyIds: Array.from(techniqueStrategyIds.get(t.id) || []),
      };
    })
    .filter(t => !!t.attackId)
    .sort((a, b) => a.attackId.localeCompare(b.attackId));

  const tacticList = tactics.map(t => ({
    id: t.id,
    name: t.name,
    shortname: t.x_mitre_shortname,
    attackId: externalAttackId(t),
    description: t.description || "",
  })).sort((a, b) => a.name.localeCompare(b.name));

  // Build group -> techniques (uses relationships where source=intrusion-set, target=attack-pattern)
  const techniqueIdSet = new Set(techniques.map(t => t.id));
  const groupTechniques = new Map();      // groupId -> Set(techniqueId)
  const techniqueGroups = new Map();      // techniqueId -> Set(groupId)
  for (const r of usesRels) {
    if (!techniqueIdSet.has(r.target_ref)) continue;
    const src = byId.get(r.source_ref);
    if (!src || src.type !== "intrusion-set") continue;
    if (!groupTechniques.has(r.source_ref)) groupTechniques.set(r.source_ref, new Set());
    groupTechniques.get(r.source_ref).add(r.target_ref);
    if (!techniqueGroups.has(r.target_ref)) techniqueGroups.set(r.target_ref, new Set());
    techniqueGroups.get(r.target_ref).add(r.source_ref);
  }

  const groupList = intrusionSets.map(g => ({
    id: g.id,
    stixId: g.id,
    attackId: externalAttackId(g),
    name: g.name,
    aliases: (g.aliases || []).filter(a => a !== g.name),
    description: g.description || "",
    techniqueIds: Array.from(groupTechniques.get(g.id) || []),
  })).filter(g => g.attackId).sort((a, b) => a.name.localeCompare(b.name));

  // Collect unique platforms across data sources
  const platforms = new Set();
  for (const ds of dataSourceList) ds.platforms.forEach(p => platforms.add(p));

  // ATT&CK version (best effort: from bundle or marking definitions)
  const versionMarking = objects.find(o => o.type === "x-mitre-collection");
  const version = versionMarking?.x_mitre_version || bundle.spec_version || "unknown";

  // v18+ exports: log sources, analytics, detection strategies (already
  // resolved above). Sort arrays for stable rendering.
  const logSourceList = Array.from(logSourceById.values())
    .map(ls => ({
      id: ls.id,
      name: ls.name,
      channel: ls.channel,
      componentIds: Array.from(ls.componentIds),
      platforms: Array.from(ls.platforms),
    }))
    .sort((a, b) => (a.name + "/" + a.channel).localeCompare(b.name + "/" + b.channel));
  const analyticList = Array.from(analyticById.values())
    .sort((a, b) => a.name.localeCompare(b.name));
  const detectionStrategyList = Array.from(detectionStrategyById.values())
    .sort((a, b) => (a.attackId || a.name).localeCompare(b.attackId || b.name));

  return {
    meta: { ...meta, version, objectCount: objects.length },
    dataSources: dataSourceList,
    dataComponents: dataSourceList.flatMap(ds => ds.components),
    techniques: techniqueList,
    tactics: tacticList,
    groups: groupList,
    platforms: Array.from(platforms).sort(),
    logSources: logSourceList,
    analytics: analyticList,
    detectionStrategies: detectionStrategyList,
    // lookup helpers
    byId,
    componentById: new Map(dataSourceList.flatMap(ds => ds.components.map(c => [c.id, c]))),
    techniqueById: new Map(techniqueList.map(t => [t.id, t])),
    techniqueByAttackId: new Map(techniqueList.map(t => [t.attackId, t])),
    dataSourceById: new Map(dataSourceList.map(ds => [ds.id, ds])),
    groupById: new Map(groupList.map(g => [g.id, g])),
    groupByAttackId: new Map(groupList.map(g => [g.attackId, g])),
    logSourceById: new Map(logSourceList.map(ls => [ls.id, ls])),
    analyticById: new Map(analyticList.map(a => [a.id, a])),
    detectionStrategyById: new Map(detectionStrategyList.map(s => [s.id, s])),
    techniqueGroups, // techniqueId -> Set(groupId)
  };
}
