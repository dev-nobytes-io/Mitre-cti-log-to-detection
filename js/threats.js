// Threat-group selection and gap analysis. Modeled after DeTT&CT's
// group-administration YAML.
//
// Schema:
// {
//   version: 1.0,
//   file_type: "group-administration",
//   name: "Selected groups",
//   groups: [
//     { group_name: "APT29", campaign: "", technique_id: "all", enabled: true }
//   ]
// }

const STORAGE_KEY = "attack-threats-v1";

export function emptyThreatSelection() {
  return { version: 1.0, file_type: "group-administration", name: "Selected groups", groups: [] };
}

export function loadThreats() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return emptyThreatSelection();
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") return migrate(parsed);
  } catch (_) {}
  return emptyThreatSelection();
}

export function saveThreats(t) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(t));
}

export function resetThreats() {
  localStorage.removeItem(STORAGE_KEY);
  return emptyThreatSelection();
}

function migrate(t) {
  if (!Array.isArray(t.groups)) t.groups = [];
  if (!t.version) t.version = 1.0;
  if (!t.file_type) t.file_type = "group-administration";
  if (!t.name) t.name = "Selected groups";
  return t;
}

export function isGroupSelected(threats, group) {
  if (!group) return false;
  const id = group.attackId?.toUpperCase();
  return (threats.groups || []).some(g => g.enabled && (g.group_name?.toUpperCase() === id || g.group_name?.toLowerCase() === group.name.toLowerCase()));
}

export function setGroupSelected(threats, group, enabled) {
  if (!group) return threats;
  const idx = (threats.groups || []).findIndex(g =>
    g.group_name?.toUpperCase() === group.attackId?.toUpperCase() ||
    g.group_name?.toLowerCase() === group.name.toLowerCase());
  if (idx >= 0) {
    threats.groups[idx].enabled = enabled;
  } else if (enabled) {
    threats.groups.push({ group_name: group.attackId || group.name, campaign: "", technique_id: "all", enabled: true });
  }
  return threats;
}

export function clearSelection(threats) {
  threats.groups = [];
  return threats;
}

// Resolve selected groups to ATT&CK group objects.
export function selectedGroups(threats, attack) {
  if (!attack?.groups) return [];
  const enabled = (threats.groups || []).filter(g => g.enabled);
  const out = [];
  for (const sel of enabled) {
    const key = (sel.group_name || "").trim();
    if (!key) continue;
    const byId = attack.groupByAttackId.get(key.toUpperCase());
    if (byId) { out.push(byId); continue; }
    const byName = attack.groups.find(g =>
      g.name.toLowerCase() === key.toLowerCase() ||
      (g.aliases || []).some(a => a.toLowerCase() === key.toLowerCase()));
    if (byName) out.push(byName);
  }
  return out;
}

// Cross-reference selected groups' techniques with detection coverage.
// coverageRowsByStixId is a Map(techniqueStixId -> coverage row from coverage.js).
export function gapAnalysis(threats, attack, coverageRowsByStixId) {
  const groups = selectedGroups(threats, attack);
  if (!groups.length) {
    return { groups: [], threatTechniques: [], summary: { totalThreats: 0, covered: 0, partial: 0, gaps: 0, undetectable: 0, riskAccepted: 0 } };
  }
  const techIdToGroups = new Map();
  for (const g of groups) {
    for (const tid of g.techniqueIds) {
      if (!techIdToGroups.has(tid)) techIdToGroups.set(tid, []);
      techIdToGroups.get(tid).push(g);
    }
  }
  const rows = [];
  for (const [tid, gs] of techIdToGroups) {
    const tech = attack.techniqueById.get(tid);
    if (!tech) continue;
    const cov = coverageRowsByStixId.get(tid);
    const weighted = cov ? cov.weightedScore : 0;
    const ratio = cov ? cov.ratio : 0;
    const detectable = cov ? cov.hasDetections : false;
    const riskAccepted = !!(cov && cov.riskAccepted);
    // chunk 10: risk-accepted wins over gap so users see the
    // acknowledged-gap bucket distinct from "true uncovered."
    let status;
    if (riskAccepted) status = "risk_accepted";
    else if (!detectable) status = "undetectable";
    else if (weighted <= 0) status = "gap";
    else if (ratio >= 1) status = "covered";
    else status = "partial";
    // Preventive-control dimension — copied straight off the coverage row
    // computeCoverage() already attached it to (additive there too; see
    // coverage.js). Lets a "gap" (no detection) be reframed as "mitigated
    // but undetected" rather than a bare, undifferentiated red flag.
    const mitigationIds = cov?.mitigationIds || [];
    const mitigationScore = cov?.mitigationScore || 0;
    rows.push({
      tech,
      groups: gs,
      groupCount: gs.length,
      weightedScore: weighted,
      ratio,
      hasDetections: detectable,
      riskAccepted,
      status,
      mitigationIds,
      mitigationScore,
      // Covers both flavors of "no effective detection right now" — a
      // detectable-in-principle gap and a technique the bundle has no
      // detection modeled for at all.
      mitigatedGap: (status === "gap" || status === "undetectable") && mitigationScore > 0,
    });
  }
  rows.sort((a, b) => {
    const order = { gap: 0, undetectable: 1, partial: 2, risk_accepted: 3, covered: 4 };
    if (order[a.status] !== order[b.status]) return order[a.status] - order[b.status];
    if (b.groupCount !== a.groupCount) return b.groupCount - a.groupCount;
    return (a.tech.attackId || "").localeCompare(b.tech.attackId || "");
  });
  const summary = {
    totalThreats: rows.length,
    covered: rows.filter(r => r.status === "covered").length,
    partial: rows.filter(r => r.status === "partial").length,
    gaps: rows.filter(r => r.status === "gap").length,
    undetectable: rows.filter(r => r.status === "undetectable").length,
    riskAccepted: rows.filter(r => r.status === "risk_accepted").length,
    // Preventive-control overlay (additive; doesn't change the buckets above).
    mitigatedGaps: rows.filter(r => r.mitigatedGap).length,
  };
  return { groups, threatTechniques: rows, summary };
}

// --- import / export ---

export function exportThreatsYaml(threats) {
  const doc = {
    version: 1.0,
    file_type: "group-administration",
    name: threats.name || "Selected groups",
    groups: (threats.groups || []).map(g => ({
      group_name: g.group_name,
      campaign: g.campaign || "",
      technique_id: g.technique_id || "all",
      enabled: g.enabled !== false,
    })),
  };
  return window.jsyaml.dump(doc, { lineWidth: 120, noRefs: true });
}

export function importThreatsYaml(text) {
  const doc = window.jsyaml.load(text);
  return importThreatsDoc(doc);
}

export function importThreatsJson(text) {
  return importThreatsDoc(JSON.parse(text));
}

function importThreatsDoc(doc) {
  if (!doc || typeof doc !== "object") throw new Error("Invalid threats document");
  const t = emptyThreatSelection();
  t.name = doc.name || t.name;
  if (Array.isArray(doc.groups)) {
    t.groups = doc.groups.map(g => ({
      group_name: g.group_name || g.name || g.id,
      campaign: g.campaign || "",
      technique_id: g.technique_id || "all",
      enabled: g.enabled !== false,
    })).filter(g => g.group_name);
  }
  return t;
}

// Build a Navigator layer for the selected groups: each technique scored by
// the number of selected groups using it (1..N). Optionally combined with
// the detection-coverage heatmap to produce a "gap" layer.
export function buildThreatLayer({ attack, threats, mode = "groups", coverageRowsByStixId, name = "", description = "" } = {}) {
  const groups = selectedGroups(threats, attack);
  if (!groups.length) return null;

  const techCounts = new Map();
  for (const g of groups) {
    for (const tid of g.techniqueIds) {
      techCounts.set(tid, (techCounts.get(tid) || 0) + 1);
    }
  }

  const techniques = [];
  for (const [tid, count] of techCounts) {
    const tech = attack.techniqueById.get(tid);
    if (!tech) continue;
    const cov = coverageRowsByStixId?.get(tid);
    let score, comment;
    if (mode === "gaps") {
      // Score = unmet coverage: groups using it × (1 - coverage ratio)
      const ratio = cov?.ratio || 0;
      const detectable = cov?.hasDetections ? 1 : 0;
      score = Math.round(count * (1 - ratio) * 100) / 100;
      const status = !detectable ? "no detections defined"
        : (cov.weightedScore > 0 && ratio >= 1) ? "fully covered"
        : (cov.weightedScore > 0) ? "partial" : "uncovered";
      comment = `${count} selected group${count === 1 ? "" : "s"}; status: ${status}`;
    } else {
      score = count;
      comment = `Used by ${count} selected group${count === 1 ? "" : "s"}: ${groups.filter(g => g.techniqueIds.includes(tid)).map(g => g.attackId).join(", ")}`;
    }
    techniques.push({
      techniqueID: tech.attackId,
      score,
      color: "",
      comment,
      enabled: true,
      metadata: groups.filter(g => g.techniqueIds.includes(tid)).map(g => ({ name: "Group", value: `${g.attackId} ${g.name}` })),
    });
  }

  const maxScore = techniques.reduce((m, t) => Math.max(m, t.score), 0) || 1;
  const layerName = name || (mode === "gaps" ? "Threat coverage gaps" : "Threat groups overlay");
  const layerDesc = description || (mode === "gaps"
    ? `Techniques used by ${groups.length} selected groups, weighted by uncovered ratio. High score = bigger gap.`
    : `Techniques used by ${groups.length} selected groups. Score = number of selected groups using the technique.`);

  return {
    name: layerName,
    versions: { attack: String(attack.meta?.version || "16"), navigator: "5.1.0", layer: "4.5" },
    domain: attack.meta?.domain || "enterprise-attack",
    description: layerDesc,
    sorting: 3,
    layout: { layout: "side", aggregateFunction: "average", showID: false, showName: true, showAggregateScores: true, countUnscored: false },
    techniques,
    gradient: { colors: mode === "gaps" ? ["#ffe0b3", "#b30000"] : ["#cce5ff", "#003366"], minValue: 0, maxValue: maxScore },
    legendItems: [],
    metadata: [
      { name: "Generated", value: new Date().toISOString() },
      { name: "Mode", value: mode },
      { name: "Groups selected", value: String(groups.length) },
      ...groups.map(g => ({ name: g.attackId, value: g.name })),
    ],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
  };
}
