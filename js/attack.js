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

function indexBundle(bundle, meta) {
  const objects = bundle.objects || [];
  const byId = new Map();
  for (const o of objects) byId.set(o.id, o);

  const dataSources = [];     // x-mitre-data-source
  const dataComponents = [];  // x-mitre-data-component
  const techniques = [];      // attack-pattern (active)
  const tactics = [];         // x-mitre-tactic
  const intrusionSets = [];   // intrusion-set (threat-actor groups)
  const detectsRels = [];     // relationship type=detects
  const usesRels = [];        // relationship type=uses (group/software -> technique)

  for (const o of objects) {
    if (o.x_mitre_deprecated || o.revoked) continue;
    switch (o.type) {
      case "x-mitre-data-source": dataSources.push(o); break;
      case "x-mitre-data-component": dataComponents.push(o); break;
      case "attack-pattern": techniques.push(o); break;
      case "x-mitre-tactic": tactics.push(o); break;
      case "intrusion-set": intrusionSets.push(o); break;
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

  // Normalize objects we care about
  const dataSourceList = dataSources.map(ds => {
    const components = (componentsBySource.get(ds.id) || []).map(dc => ({
      id: dc.id,
      stixId: dc.id,
      name: dc.name,
      description: dc.description || "",
      sourceId: ds.id,
      techniqueIds: Array.from(componentTechniques.get(dc.id) || []),
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

  return {
    meta: { ...meta, version, objectCount: objects.length },
    dataSources: dataSourceList,
    dataComponents: dataSourceList.flatMap(ds => ds.components),
    techniques: techniqueList,
    tactics: tacticList,
    groups: groupList,
    platforms: Array.from(platforms).sort(),
    // lookup helpers
    byId,
    componentById: new Map(dataSourceList.flatMap(ds => ds.components.map(c => [c.id, c]))),
    techniqueById: new Map(techniqueList.map(t => [t.id, t])),
    techniqueByAttackId: new Map(techniqueList.map(t => [t.attackId, t])),
    dataSourceById: new Map(dataSourceList.map(ds => [ds.id, ds])),
    groupById: new Map(groupList.map(g => [g.id, g])),
    groupByAttackId: new Map(groupList.map(g => [g.attackId, g])),
    techniqueGroups, // techniqueId -> Set(groupId)
  };
}
