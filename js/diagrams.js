// Mermaid diagram generators.
// Each function returns a Mermaid source string. They escape labels and
// use stable, alphanumeric node IDs so re-renders don't trip the parser.

export function conceptualDiagram() {
  return `flowchart LR
    log[/"Raw log<br/>(EDR, Sysmon, firewall…)"/]:::raw
    src["ATT&CK Component Category<br/>e.g. Process"]:::ds
    cmp["ATT&CK Data Component<br/>e.g. Process Creation"]:::dc
    rel{{"detects relationship<br/>(STIX)"}}:::rel
    tech["ATT&CK Technique<br/>e.g. T1059"]:::tech
    tac["ATT&CK Tactic<br/>e.g. Execution"]:::tac
    nav[("Navigator layer<br/>score = max × ratio")]:::out

    mit["ATT&CK Mitigation<br/>e.g. M1032"]:::mit
    d3f["D3FEND Sub-mitigation<br/>e.g. D3-MFA"]:::d3f
    ctrl["NIST 800-53 / ISM control<br/>e.g. AC-2(1) / ISM-1546"]:::ctrl

    log --> src
    src --> cmp
    cmp --> rel
    rel --> tech
    tech --> tac
    tech -. "weighted by your<br/>visibility score" .-> nav

    mit -->|"mitigates<br/>(preventive, not detective)"| tech
    mit -.->|"D3FEND sub-mitigation"| d3f
    d3f -.->|"D3FEND/custom crosswalk"| ctrl

    classDef raw fill:#1e293b,stroke:#475569,color:#cbd5e1;
    classDef ds  fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef dc  fill:#1d3b32,stroke:#3fb950,color:#e6edf3;
    classDef rel fill:#3b2c1d,stroke:#d29922,color:#fef3c7;
    classDef tech fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3;
    classDef tac fill:#2b1d3b,stroke:#a78bfa,color:#e6edf3;
    classDef out fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef mit  fill:#1d3320,stroke:#7ee787,color:#e6edf3;
    classDef d3f  fill:#241d3b,stroke:#a78bfa,color:#e6edf3;
    classDef ctrl fill:#241d3b,stroke:#a78bfa,color:#e6edf3,stroke-dasharray: 3 3;
  `;
}

// Diagram for a single data source: source -> components -> techniques.
export function sourceDiagram({ dataSource, attack, componentScores, maxTechniquesPerComponent = 20, onlyCovered = false }) {
  if (!dataSource) return null;
  const lines = ["flowchart LR"];
  const sId = nodeId("S", dataSource.id);
  const sourceEntry = lookupSourceScore(dataSource, componentScores);
  lines.push(`  ${sId}["${escape(dataSource.name)}<br/><i>${escape(dataSource.attackId || "")}</i>"]:::ds`);

  let drawnTech = 0;
  const techIdsSeen = new Set();
  for (const dc of dataSource.components) {
    const cId = nodeId("C", dc.id);
    const eff = componentScores.get(dc.id);
    const score = eff?.score ?? 0;
    const cls = score > 0 ? "dcCov" : "dcUnc";
    lines.push(`  ${cId}["${escape(dc.name)}<br/><i>score ${score}</i>"]:::${cls}`);
    lines.push(`  ${sId} --> ${cId}`);

    const techIds = dc.techniqueIds.slice(0, maxTechniquesPerComponent);
    for (const tid of techIds) {
      const tech = attack.techniqueById.get(tid);
      if (!tech) continue;
      if (onlyCovered && score === 0) continue;
      const tNode = nodeId("T", tech.id);
      if (!techIdsSeen.has(tech.id)) {
        const tCls = score > 0 ? "techCov" : "techUnc";
        lines.push(`  ${tNode}["${escape(tech.attackId)}<br/>${escape(truncate(tech.name, 32))}"]:::${tCls}`);
        techIdsSeen.add(tech.id);
      }
      lines.push(`  ${cId} --> ${tNode}`);
      drawnTech++;
    }
    if (dc.techniqueIds.length > techIds.length) {
      const moreId = `${cId}_more`;
      lines.push(`  ${moreId}(["+${dc.techniqueIds.length - techIds.length} more"]):::more`);
      lines.push(`  ${cId} --> ${moreId}`);
    }
  }

  lines.push(classDefs());
  if (drawnTech === 0) {
    lines.push(`  empty["No techniques to display"]:::more`);
    lines.push(`  ${sId} --> empty`);
  }
  return lines.join("\n");
}

// Diagram for a single technique: components that detect it (with their
// parent data sources) on the detective side, and mitigations (with their
// D3FEND/NIST/ISM sub-mitigations) on the preventive side. `mitigationScores`
// (from inventory.js's effectiveMitigationScores) is optional — pass it to
// colour mitigation nodes by whether they've been scored.
export function techniqueDiagram({ technique, attack, componentScores, mitigationScores }) {
  if (!technique) return null;
  const lines = ["flowchart RL"];
  const tNode = nodeId("T", technique.id);
  lines.push(`  ${tNode}["${escape(technique.attackId)}: ${escape(truncate(technique.name, 40))}<br/><i>${escape(technique.tactics.join(", "))}</i>"]:::techMain`);

  if (!technique.componentIds.length) {
    lines.push(`  none["No detecting data components defined"]:::more`);
    lines.push(`  none --> ${tNode}`);
  } else {
    const sourcesSeen = new Set();
    for (const cid of technique.componentIds) {
      const dc = attack.componentById.get(cid);
      if (!dc) continue;
      const ds = attack.dataSourceById.get(dc.sourceId);
      const cId = nodeId("C", dc.id);
      const sId = nodeId("S", dc.sourceId);
      const eff = componentScores.get(dc.id);
      const score = eff?.score ?? 0;
      const cCls = score > 0 ? "dcCov" : "dcUnc";
      if (!sourcesSeen.has(dc.sourceId)) {
        lines.push(`  ${sId}["${escape(ds?.name || "Unknown source")}"]:::ds`);
        sourcesSeen.add(dc.sourceId);
      }
      lines.push(`  ${cId}["${escape(dc.name)}<br/><i>score ${score}</i>"]:::${cCls}`);
      lines.push(`  ${cId} --> ${tNode}`);
      lines.push(`  ${sId} --> ${cId}`);
    }
  }

  // Preventive-control branch: mitigations -> technique, each with its
  // D3FEND/NIST/ISM sub-mitigations. NIST controls are folded into the
  // D3FEND node's label (rather than their own nodes) to keep the node
  // count bounded — a single mitigation can carry 4+ NIST controls.
  const mitigationIds = technique.mitigationIds || [];
  if (mitigationIds.length) {
    const mitScores = mitigationScores || new Map();
    const MIT_CAP = 8;
    const SUB_CAP = 12;
    const capped = mitigationIds.slice(0, MIT_CAP);
    let subCount = 0;
    for (const mid of capped) {
      const m = attack.mitigationById?.get(mid);
      if (!m) continue;
      const score = mitScores.get(m.attackId)?.score || 0;
      const mNode = nodeId("M", m.id);
      const mCls = score > 0 ? "mitLit" : "mitUnlit";
      const idLabel = m.custom ? "custom" : m.attackId;
      lines.push(`  ${mNode}["🛡 ${escape(idLabel)}<br/>${escape(truncate(m.name, 32))}<br/><i>${score > 0 ? "maturity " + score + "/5" : "not assessed"}</i>"]:::${mCls}`);
      lines.push(`  ${mNode} --> ${tNode}`);
      const subs = [
        ...(m.d3fend || []).map(d => ({ kind: "D3FEND", id: d.id, nist: d.nist })),
        ...(m.customD3fend || []).map(d => ({ kind: "D3FEND", id: d.id, nist: [] })),
        ...(m.customNist || []).map(d => ({ kind: "NIST", id: d.id, nist: [] })),
        ...(m.customIsm || []).map(d => ({ kind: "ISM", id: d.id, nist: [] })),
      ];
      for (const s of subs) {
        if (subCount >= SUB_CAP) break;
        const sNode = nodeId("D3", `${m.id}:${s.kind}:${s.id}`);
        const nistLabel = s.nist?.length ? `<br/><i>NIST ${escape(s.nist.slice(0, 3).join(", "))}${s.nist.length > 3 ? "…" : ""}</i>` : "";
        lines.push(`  ${sNode}["${escape(s.kind)} ${escape(s.id)}${nistLabel}"]:::d3sub`);
        lines.push(`  ${mNode} --> ${sNode}`);
        subCount++;
      }
    }
    if (mitigationIds.length > capped.length) {
      const moreId = `${tNode}_mitmore`;
      lines.push(`  ${moreId}(["+${mitigationIds.length - capped.length} more mitigations"]):::more`);
      lines.push(`  ${moreId} --> ${tNode}`);
    }
  }

  lines.push(classDefs());
  return lines.join("\n");
}

// Bar-chart-style overview using Mermaid's xychart-beta (covered vs total per data source).
export function overviewDiagram({ attack, componentScores, topN = 12 }) {
  const ranked = attack.dataSources
    .map(ds => {
      const totalTech = new Set();
      const coveredTech = new Set();
      for (const dc of ds.components) {
        const score = componentScores.get(dc.id)?.score ?? 0;
        for (const tid of dc.techniqueIds) {
          totalTech.add(tid);
          if (score > 0) coveredTech.add(tid);
        }
      }
      return { name: ds.name, total: totalTech.size, covered: coveredTech.size };
    })
    .filter(r => r.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, topN);

  if (!ranked.length) return null;

  // Use a flowchart with bar-like nodes — xychart-beta is finicky and not as readable for this.
  const lines = ["flowchart TB"];
  lines.push(`  title["Detection breadth: covered / total techniques per component category"]:::title`);
  for (const r of ranked) {
    const id = nodeId("OV", r.name);
    const pct = r.total ? Math.round((r.covered / r.total) * 100) : 0;
    const bar = renderBar(pct);
    const cls = r.covered === 0 ? "ovUnc" : (r.covered === r.total ? "ovFull" : "ovPart");
    lines.push(`  ${id}["${escape(r.name)} &nbsp; ${bar} &nbsp; ${r.covered}/${r.total} (${pct}%)"]:::${cls}`);
  }
  // Chain top -> bottom for vertical layout
  const ids = ranked.map(r => nodeId("OV", r.name));
  lines.push(`  title --> ${ids[0]}`);
  for (let i = 1; i < ids.length; i++) lines.push(`  ${ids[i-1]} --> ${ids[i]}`);
  lines.push(`
    classDef title fill:transparent,stroke:transparent,color:#8b949e,font-size:11px;
    classDef ovFull fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef ovPart fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef ovUnc  fill:#2a2f3a,stroke:#475569,color:#cbd5e1;
  `);
  return lines.join("\n");
}

function renderBar(pct) {
  const filled = Math.round(pct / 5); // 0..20
  const empty = 20 - filled;
  return "▰".repeat(filled) + "▱".repeat(empty);
}

// Log Source Utility cascade: shows what coverage a particular set of
// log sources unlocks. Renders the v18+ chain top-to-bottom:
//
//   Log Sources -> Data Components -> Analytics -> Detection Strategies
//      -> Techniques -> Threat Groups (using those techniques)
//
// Nodes are coloured by lit/unlit status so the diagram answers
// the user-facing question "why am I logging eventcode 1 / 4624?":
// each link upward shows the threat-intel value the log carries.
//
// Args:
//   selectedLogSourceIds: Iterable<string>      log-source ids the user picked
//   logSourceScores:      Map<id, {score,...}>  effective log-source scores (drives lit/unlit)
//   threats:              optional state.threats — only the *selected* groups
//                         are highlighted; if no groups selected, all groups
//                         using each technique are shown.
export function logSourceCascadeDiagram({ attack, selectedLogSourceIds, logSourceScores, threats, analyticAggregation = "min" }) {
  const lsIds = Array.from(selectedLogSourceIds || []);
  if (!attack || lsIds.length === 0) return null;

  const aggregate = analyticAggregation === "avg"
    ? (vs) => vs.length ? vs.reduce((s, v) => s + v, 0) / vs.length : 0
    : (vs) => vs.length ? Math.min(...vs) : 0;

  const lsSet = new Set(lsIds);
  const lines = ["flowchart LR"];

  // 1. Selected log sources
  const lsNodes = [];
  for (const lsId of lsIds) {
    const ls = attack.logSourceById?.get(lsId);
    if (!ls) continue;
    const score = logSourceScores?.get(lsId)?.score || 0;
    const cls = score > 0 ? "lsLit" : "lsUnlit";
    const id = nodeId("LS", lsId);
    lines.push(`  ${id}["${escape(ls.name)}<br/>${escape(ls.channel || "")}<br/><i>score ${score}</i>"]:::${cls}`);
    lsNodes.push({ id, lsId, ls, score });
  }

  // 2. Data components fed by any of those log sources
  const componentSet = new Map(); // compId -> { dc, contributingLsIds: Set }
  for (const lsId of lsIds) {
    const ls = attack.logSourceById?.get(lsId);
    for (const cid of ls?.componentIds || []) {
      if (!componentSet.has(cid)) componentSet.set(cid, { dc: attack.componentById?.get(cid), contributingLsIds: new Set() });
      componentSet.get(cid).contributingLsIds.add(lsId);
    }
  }
  for (const [cid, { dc, contributingLsIds }] of componentSet) {
    if (!dc) continue;
    const id = nodeId("DC", cid);
    lines.push(`  ${id}["${escape(dc.name)}"]:::dc`);
    for (const lsId of contributingLsIds) lines.push(`  ${nodeId("LS", lsId)} --> ${id}`);
  }

  // 3. Analytics that reference any of those components.
  // An analytic is *lit* iff every one of its required log sources has
  // score > 0. The diagram shades it green only on full coverage.
  const analyticSet = new Set();
  const analyticInfo = new Map(); // analyticId -> { lit, score, refs: [{lsId, score}] }
  for (const an of attack.analytics || []) {
    const refs = (an.logSourceIds || []).map(id => ({ lsId: id, score: logSourceScores?.get(id)?.score || 0 }));
    const touchesSelection = refs.some(r => lsSet.has(r.lsId));
    if (!touchesSelection) continue;
    const lit = refs.length > 0 && refs.every(r => r.score > 0);
    const score = lit ? aggregate(refs.map(r => r.score)) : 0;
    analyticSet.add(an.id);
    analyticInfo.set(an.id, { lit, score, refs, name: an.name });
    const id = nodeId("AN", an.id);
    const cls = lit ? "anLit" : "anUnlit";
    lines.push(`  ${id}["${escape(truncate(an.name, 40))}<br/><i>${refs.filter(r => r.score > 0).length}/${refs.length} log sources lit · ${lit ? "score " + score.toFixed(1) : "unlit"}</i>"]:::${cls}`);
    for (const cid of an.componentIds || []) {
      if (componentSet.has(cid)) lines.push(`  ${nodeId("DC", cid)} --> ${id}`);
    }
  }

  // 4. Detection strategies bundling those analytics
  const strategySet = new Set();
  const strategyInfo = new Map(); // strategyId -> { lit, score }
  for (const st of attack.detectionStrategies || []) {
    const myAns = (st.analyticIds || []).filter(id => analyticSet.has(id));
    if (myAns.length === 0) continue;
    const litAns = myAns.filter(id => analyticInfo.get(id)?.lit);
    const lit = litAns.length > 0;
    const score = lit ? Math.max(...litAns.map(id => analyticInfo.get(id).score)) : 0;
    strategySet.add(st.id);
    strategyInfo.set(st.id, { lit, score });
    const id = nodeId("DS", st.id);
    const cls = lit ? "dsLit" : "dsUnlit";
    lines.push(`  ${id}["${escape(st.attackId || "")}<br/>${escape(truncate(st.name, 40))}<br/><i>${litAns.length}/${myAns.length} analytics lit</i>"]:::${cls}`);
    for (const aid of myAns) lines.push(`  ${nodeId("AN", aid)} --> ${id}`);
  }

  // 5. Techniques detected by those strategies
  const techniqueSet = new Set();
  for (const sid of strategySet) {
    const st = attack.detectionStrategyById?.get(sid);
    for (const tid of st?.techniqueIds || []) techniqueSet.add(tid);
  }
  for (const tid of techniqueSet) {
    const tech = attack.techniqueById?.get(tid);
    if (!tech) continue;
    const detectingStrats = (tech.strategyIds || []).filter(sid => strategySet.has(sid));
    const litStrats = detectingStrats.filter(sid => strategyInfo.get(sid)?.lit);
    const lit = litStrats.length > 0;
    const id = nodeId("T", tid);
    const cls = lit ? "techLit" : "techUnlit";
    lines.push(`  ${id}["${escape(tech.attackId)}<br/>${escape(truncate(tech.name, 32))}"]:::${cls}`);
    for (const sid of detectingStrats) lines.push(`  ${nodeId("DS", sid)} --> ${id}`);
  }

  // 6. Threat groups that use those techniques (highlighted by selection if any)
  const selectedGroupIds = new Set(threats?.groups?.filter(g => g.selected).map(g => g.attackId) || []);
  const groupSet = new Map(); // groupId -> { group, techIds: Set, selected: bool }
  for (const tid of techniqueSet) {
    const groupIds = attack.techniqueGroups?.get(tid) || new Set();
    for (const gid of groupIds) {
      const g = attack.groupById?.get(gid);
      if (!g) continue;
      if (!groupSet.has(gid)) groupSet.set(gid, { group: g, techIds: new Set(), selected: selectedGroupIds.has(g.attackId) });
      groupSet.get(gid).techIds.add(tid);
    }
  }
  // Cap rendered groups so the diagram stays readable; prefer selected groups.
  const groupList = Array.from(groupSet.values());
  groupList.sort((a, b) => Number(b.selected) - Number(a.selected) || b.techIds.size - a.techIds.size);
  const renderedGroups = groupList.slice(0, 12);
  for (const { group, techIds, selected } of renderedGroups) {
    const id = nodeId("G", group.id);
    const cls = selected ? "grpSel" : "grpAny";
    lines.push(`  ${id}["${escape(group.attackId || "")}<br/>${escape(truncate(group.name, 24))}"]:::${cls}`);
    for (const tid of techIds) lines.push(`  ${nodeId("T", tid)} --> ${id}`);
  }
  if (groupList.length > renderedGroups.length) {
    const moreId = "Gmore";
    lines.push(`  ${moreId}(["+${groupList.length - renderedGroups.length} more groups"]):::more`);
    if (renderedGroups[0]) lines.push(`  ${nodeId("G", renderedGroups[0].group.id)} -.-> ${moreId}`);
  }

  // Empty-state fallbacks so the user gets meaningful feedback even when
  // their selection produces no downstream nodes.
  if (componentSet.size === 0) lines.push(`  none1["No data components fed by these log sources"]:::more`);
  else if (analyticSet.size === 0) lines.push(`  none2["No analytics in this bundle reference these log sources yet"]:::more`);
  else if (techniqueSet.size === 0) lines.push(`  none3["Strategies don't yet detect any techniques"]:::more`);

  lines.push(cascadeClassDefs());
  return lines.join("\n");
}

function classDefs() {
  return `
    classDef ds    fill:#1c2230,stroke:#2f81f7,color:#e6edf3;
    classDef dcCov fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef dcUnc fill:#2a2f3a,stroke:#475569,color:#cbd5e1;
    classDef techCov fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3;
    classDef techUnc fill:#1c1f26,stroke:#3a3f4a,color:#8b949e;
    classDef techMain fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3,stroke-width:2px;
    classDef more  fill:#161b22,stroke:#30363d,color:#8b949e;
    classDef rel   fill:#3b2c1d,stroke:#d29922,color:#fef3c7;
    classDef mitLit   fill:#0e3a2a,stroke:#7ee787,color:#dcfce7;
    classDef mitUnlit fill:#1d3320,stroke:#7ee787,color:#e6edf3;
    classDef d3sub fill:#241d3b,stroke:#a78bfa,color:#e6edf3;
  `;
}

function cascadeClassDefs() {
  return `
    classDef lsLit   fill:#0e3a2a,stroke:#3fb950,color:#dcfce7,stroke-width:2px;
    classDef lsUnlit fill:#3a2a0e,stroke:#d29922,color:#fef3c7,stroke-width:2px;
    classDef dc      fill:#1d3b32,stroke:#3fb950,color:#e6edf3;
    classDef anLit   fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef anUnlit fill:#2a2f3a,stroke:#475569,color:#cbd5e1;
    classDef dsLit   fill:#1d2b3b,stroke:#6ec1ff,color:#e6edf3,stroke-width:2px;
    classDef dsUnlit fill:#1c1f26,stroke:#3a3f4a,color:#8b949e;
    classDef techLit fill:#0e3a2a,stroke:#3fb950,color:#dcfce7;
    classDef techUnlit fill:#1c1f26,stroke:#3a3f4a,color:#8b949e;
    classDef grpSel  fill:#3b1d2b,stroke:#f85149,color:#fee2e2,stroke-width:2px;
    classDef grpAny  fill:#2b1d3b,stroke:#a78bfa,color:#e6edf3;
    classDef more    fill:#161b22,stroke:#30363d,color:#8b949e;
  `;
}



function lookupSourceScore(ds, compScores) {
  for (const dc of ds.components) {
    const v = compScores.get(dc.id);
    if (v) return v;
  }
  return null;
}

// Mermaid IDs must match /[A-Za-z][A-Za-z0-9_]*/. Hash to keep them stable & short.
function nodeId(prefix, raw) {
  let h = 0;
  const s = String(raw);
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `${prefix}_${h.toString(36)}`;
}

function escape(s) {
  // Mermaid uses double-quoted labels; escape quotes and pipe characters.
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/\|/g, "&#124;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function truncate(s, n) {
  if (!s) return "";
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}
