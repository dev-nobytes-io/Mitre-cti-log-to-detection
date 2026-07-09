// User-entered "custom mappings": mitigations/controls MITRE/D3FEND don't
// ship, plus relations tying them to the loaded ATT&CK bundle. This is the
// escape hatch for frameworks with no published crosswalk at all — ISM
// (the Australian Information Security Manual) has no official ATT&CK or
// D3FEND mapping anywhere, so its entries can only ever come from here.
//
// Stored inside the inventory object (inv.custom_objects[] /
// inv.custom_relations[], see inventory.js's schema comment) so they
// persist to localStorage and round-trip through YAML/JSON export exactly
// like everything else. Merged onto the loaded AttackData at render time
// via mergeCustomData() — the merge never mutates the original STIX-parsed
// data, so calling it again after every edit is always safe.
//
// Exposes:
//   RELATION_TYPES
//   addCustomMitigation(inv, {name, description}) -> id
//   removeCustomObject(inv, id)
//   addCustomRelation(inv, {sourceRef, relation, targetRef, targetLabel, comment}) -> id
//   removeCustomRelation(inv, id)
//   mergeCustomData(attack, inv) -> attack (mutated in place, idempotent)

export const RELATION_TYPES = [
  { id: "mitigates", label: "Mitigates a technique", targetKind: "technique" },
  { id: "maps-to-d3fend", label: "Maps to a D3FEND technique", targetKind: "text" },
  { id: "maps-to-nist", label: "Maps to a NIST SP 800-53 control", targetKind: "text" },
  { id: "maps-to-ism", label: "Maps to an ISM (Australian) control", targetKind: "text" },
];

function slug(s) {
  return String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
}
function uid(prefix) {
  return `${prefix}--${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
}

export function addCustomMitigation(inv, { name, description = "" }) {
  if (!Array.isArray(inv.custom_objects)) inv.custom_objects = [];
  const id = uid(`custom-mitigation-${slug(name)}`);
  inv.custom_objects.push({ id, type: "mitigation", name: name || id, description });
  return id;
}

export function removeCustomObject(inv, id) {
  inv.custom_objects = (inv.custom_objects || []).filter(o => o.id !== id);
  // Drop any relation that used it as a source (or, unusually, a target).
  inv.custom_relations = (inv.custom_relations || []).filter(r => r.sourceRef !== id && r.targetRef !== id);
  return inv;
}

export function addCustomRelation(inv, { sourceRef, relation, targetRef, targetLabel = "", comment = "" }) {
  if (!Array.isArray(inv.custom_relations)) inv.custom_relations = [];
  const id = uid("custom-relation");
  inv.custom_relations.push({ id, sourceRef, relation, targetRef: targetRef || "", targetLabel, comment });
  return id;
}

export function removeCustomRelation(inv, id) {
  inv.custom_relations = (inv.custom_relations || []).filter(r => r.id !== id);
  return inv;
}

// One pristine snapshot per AttackData instance, taken lazily on the first
// merge (i.e. after attachD3fend() has already run in onAttackLoaded()).
// Every subsequent merge — triggered by adding/removing a custom object or
// relation — rebuilds from this snapshot rather than layering onto
// whatever the previous merge left behind, so repeated calls never
// double-apply a relation.
const baselineCache = new WeakMap();
function getBaseline(attack) {
  let base = baselineCache.get(attack);
  if (!base) {
    base = {
      mitigations: attack.mitigations.map(m => ({
        ...m,
        techniqueIds: [...m.techniqueIds],
        d3fend: (m.d3fend || []).map(d => ({ ...d, nist: [...(d.nist || [])] })),
      })),
      techniqueMitigationIds: new Map(attack.techniques.map(t => [t.id, [...(t.mitigationIds || [])]])),
    };
    baselineCache.set(attack, base);
  }
  return base;
}

export function mergeCustomData(attack, inv) {
  const base = getBaseline(attack);
  const mitigations = base.mitigations.map(m => ({
    ...m,
    techniqueIds: [...m.techniqueIds],
    d3fend: m.d3fend.map(d => ({ ...d, nist: [...d.nist] })),
    customD3fend: [],
    customNist: [],
    customIsm: [],
  }));
  const mitigationById = new Map(mitigations.map(m => [m.id, m]));
  const mitigationByAttackId = new Map(mitigations.map(m => [m.attackId, m]));

  for (const obj of inv.custom_objects || []) {
    if (obj.type !== "mitigation") continue;
    const m = {
      id: obj.id, stixId: obj.id, attackId: obj.id,
      name: obj.name, description: obj.description || "",
      techniqueIds: [], d3fend: [], d3fendComment: "",
      customD3fend: [], customNist: [], customIsm: [],
      custom: true,
    };
    mitigations.push(m);
    mitigationById.set(m.id, m);
    mitigationByAttackId.set(m.attackId, m);
  }

  const techMitigationIds = new Map();
  for (const [tid, ids] of base.techniqueMitigationIds) techMitigationIds.set(tid, [...ids]);

  for (const rel of inv.custom_relations || []) {
    const src = mitigationById.get(rel.sourceRef);
    if (!src) continue;
    if (rel.relation === "mitigates") {
      const tech = attack.techniqueById?.get(rel.targetRef);
      if (!tech) continue;
      if (!src.techniqueIds.includes(rel.targetRef)) src.techniqueIds.push(rel.targetRef);
      const list = techMitigationIds.get(rel.targetRef) || [];
      if (!list.includes(src.id)) list.push(src.id);
      techMitigationIds.set(rel.targetRef, list);
    } else if (rel.relation === "maps-to-d3fend") {
      src.customD3fend.push({ id: rel.targetRef, name: rel.targetLabel || rel.targetRef, definition: rel.comment || "", custom: true });
    } else if (rel.relation === "maps-to-nist") {
      src.customNist.push({ id: rel.targetRef, name: rel.targetLabel || "", custom: true });
    } else if (rel.relation === "maps-to-ism") {
      src.customIsm.push({ id: rel.targetRef, name: rel.targetLabel || "", custom: true });
    }
  }

  attack.mitigations = mitigations;
  attack.mitigationById = mitigationById;
  attack.mitigationByAttackId = mitigationByAttackId;
  for (const t of attack.techniques) t.mitigationIds = techMitigationIds.get(t.id) || [];
  return attack;
}
